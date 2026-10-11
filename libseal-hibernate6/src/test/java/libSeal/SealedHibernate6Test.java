/*
 * libseal - field-level encryption at rest for JPA.
 * Copyright (C) 2026 aFE
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 * Additional terms under AGPL-3.0 section 7(b) apply - see NOTICE.
 */

package libSeal;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import jakarta.persistence.AttributeOverride;
import jakarta.persistence.AttributeOverrides;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.annotations.CompositeType;
import org.hibernate.boot.Metadata;
import org.hibernate.boot.MetadataSources;
import org.hibernate.boot.registry.StandardServiceRegistry;
import org.hibernate.boot.registry.StandardServiceRegistryBuilder;
import org.hibernate.cfg.AvailableSettings;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/** Hibernate 6 real + H2: composite 1 campo -> 3 columnas, JPQL por hash e IN (rotación). */
public class SealedHibernate6Test {

  /** Hibernate 6: @CompositeType no acepta params; dominio via subclase. */
  public static class EmailType extends SealedCompositeType {
    public EmailType() {
      super("customer.email", true);
    }
  }

  @SealedEntity(domain = "customer", migration = SealedMigration.LAZY)
  @EntityListeners(SealedEntityListener.class)
  @Entity
  @Table(name = "customers")
  public static class Customer {
    @Id @GeneratedValue
    public Long id;

    @CompositeType(EmailType.class)
    @AttributeOverrides({
        @AttributeOverride(name = "encrypt", column = @Column(name = "email_se", length = 2048)),
        @AttributeOverride(name = "hash", column = @Column(name = "email_sh", length = 128)),
        @AttributeOverride(name = "legacy", column = @Column(name = "email"))
    })
    @Sealed(domain = "customer.email")
    public String email;
  }

  private static SessionFactory sf;
  private static TinkSealer tinkSealer;
  private static HmacBlindIndexer indexer;
  private static String dbUrl;

  @BeforeClass
  public static void bootstrap() throws Exception {
    AeadConfig.register();
    Aead aead = KeysetHandle.generateNew(PredefinedAeadParameters.AES128_GCM)
        .getPrimitive(RegistryConfiguration.get(), Aead.class);
    tinkSealer = new TinkSealer(aead, "v1");
    byte[] pepper = new byte[32];
    java.util.Arrays.fill(pepper, (byte) 3);
    indexer = new HmacBlindIndexer(pepper, "v1");
    SealedRegistry.init(tinkSealer, indexer);

    dbUrl = "jdbc:h2:mem:sealhib6" + System.nanoTime() + ";DB_CLOSE_DELAY=-1";
    StandardServiceRegistry registry = new StandardServiceRegistryBuilder()
        .applySetting(AvailableSettings.DIALECT, "org.hibernate.dialect.H2Dialect")
        .applySetting(AvailableSettings.DRIVER, "org.h2.Driver")
        .applySetting(AvailableSettings.URL, dbUrl)
        .applySetting(AvailableSettings.USER, "sa")
        .applySetting(AvailableSettings.HBM2DDL_AUTO, "create-drop")
        .build();
    MetadataSources sources = new MetadataSources(registry);
    sources.addAnnotatedClass(Customer.class);
    Metadata metadata = sources.buildMetadata();
    sf = metadata.buildSessionFactory();
  }

  @AfterClass
  public static void close() {
    if (sf != null) sf.close();
  }

  @Test
  public void persistStoresCiphertextAndHash() throws Exception {
    Long id;
    try (Session s = sf.openSession()) {
      s.beginTransaction();
      Customer c = new Customer();
      c.email = "hola@x.com";
      s.persist(c);
      s.getTransaction().commit();
      id = c.id;
      assertNotNull(id);
    }
    try (Connection cn = DriverManager.getConnection(dbUrl, "sa", "");
         Statement st = cn.createStatement();
         ResultSet rs = st.executeQuery("SELECT email, email_se, email_sh FROM customers WHERE id=" + id)) {
      assertTrue(rs.next());
      assertEquals("hola@x.com", rs.getString(1)); // dual-write legacy
      String encrypt = rs.getString(2);
      String hash = rs.getString(3);
      assertTrue(encrypt.startsWith("v1:"));
      assertTrue(hash.startsWith("v1:"));
      // El AAD es el dominio del @Sealed: con otro dominio no abre
      assertEquals("hola@x.com", tinkSealer.unseal(encrypt, "customer.email"));
      try {
        tinkSealer.unseal(encrypt, "otro.dominio");
        assertTrue("deberia fallar por AAD", false);
      } catch (IllegalStateException expected) {
        assertTrue(true);
      }
    }
  }

  @Test
  public void loadDecryptsAndFindsByHash() {
    Long id;
    try (Session s = sf.openSession()) {
      s.beginTransaction();
      Customer c = new Customer();
      c.email = "buscar@x.com";
      s.persist(c);
      s.getTransaction().commit();
      id = c.id;
    }
    try (Session s = sf.openSession()) {
      Customer loaded = s.get(Customer.class, id);
      assertEquals("buscar@x.com", loaded.email);
      String h = indexer.hash("BUSCAR@x.com ", "customer.email"); // normalizado
      List<Customer> found = s.createQuery(
          "FROM " + Customer.class.getName() + " e WHERE e.email.hash = :h", Customer.class)
          .setParameter("h", h).getResultList();
      assertEquals(1, found.size());
      assertEquals("buscar@x.com", found.get(0).email);
      List<Customer> missing = s.createQuery(
          "FROM " + Customer.class.getName() + " e WHERE e.email.hash = :h", Customer.class)
          .setParameter("h", indexer.hash("nadie@x.com", "customer.email")).getResultList();
      assertTrue(missing.isEmpty());
    }
  }

  @Test
  public void inQueryFindsAcrossHashVersions() {
    // Ruta que usa SealedPanache con RotatingBlindIndexer: IN sobre e.email.hash
    // (una versión vieja + la activa) para encontrar filas indexadas antes de rotar.
    try (Session s = sf.openSession()) {
      s.beginTransaction();
      Customer c = new Customer();
      c.email = "rot@x.com";
      s.persist(c);
      s.getTransaction().commit();
    }
    try (Session s = sf.openSession()) {
      String active = indexer.hash("rot@x.com", "customer.email");
      List<String> candidates = java.util.Arrays.asList("v0:deadbeef", active);
      List<Customer> found = s.createQuery(
          "FROM " + Customer.class.getName() + " e WHERE e.email.hash IN :hashes", Customer.class)
          .setParameter("hashes", candidates).getResultList();
      assertEquals(1, found.size());
      assertEquals("rot@x.com", found.get(0).email);
    }
  }
}
