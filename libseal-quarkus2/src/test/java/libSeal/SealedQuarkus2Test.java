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
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Base64;
import java.util.List;
import javax.sql.DataSource;
import org.h2.jdbcx.JdbcDataSource;
import org.junit.Before;
import org.junit.Test;

/** El repositorio infiere Class<T> del genérico sin código manual (DTO limpio). */
public class SealedQuarkus2Test {

  public static class Customer {
    public Long id;
    public String email;
  }

  public static class CustomerRepository implements PanacheSealedRepository<Customer> {
  }

  /** Repo que hereda de otro: el genérico está en la superclase. */
  public static abstract class BaseRepo<T> implements PanacheSealedRepository<T> {
  }

  public static class CustomerRepoViaSuper extends BaseRepo<Customer> {
  }

  public static class RawRepository implements PanacheSealedRepository {
  }

  static final class FakeSealer implements Sealer {
    @Override public String seal(String plain, String aad) {
      if (plain == null) return null;
      return "v9:" + Base64.getEncoder().encodeToString((aad + "|" + plain).getBytes(StandardCharsets.UTF_8));
    }
    @Override public String unseal(String ct, String aad) {
      String s = new String(Base64.getDecoder().decode(ct.substring(ct.indexOf(':') + 1)), StandardCharsets.UTF_8);
      return s.substring(aad.length() + 1);
    }
  }

  @SealedEntity(domain = "customer", migration = SealedMigration.STRICT)
  @javax.persistence.Table(name = "customers")
  static class CustomerEntity {
    @javax.persistence.Id
    long id;
    @Sealed(domain = "customer.email")
    String email;
  }

  @Test
  public void repositoryInfersEntityClassImplicitly() {
    CustomerRepository repo = new CustomerRepository();
    assertEquals(Customer.class, repo.sealedEntityClass());
  }

  @Test
  public void repositoryInfersEntityClassViaSuperclassGeneric() {
    assertEquals(Customer.class, new CustomerRepoViaSuper().sealedEntityClass());
  }

  @Test
  public void rawRepositoryFailsWithActionableMessage() {
    try {
      new RawRepository().sealedEntityClass();
      assertTrue("deberia lanzar por no poder inferir Class<T>", false);
    } catch (IllegalStateException expected) {
      assertTrue(expected.getMessage().contains("SealedPanache.findSealed"));
    }
  }

  @Test
  public void startupReconcilesAndBackfillsStrict() throws Exception {
    byte[] pepper = new byte[32];
    java.util.Arrays.fill(pepper, (byte) 7);
    BlindIndexer indexer = new HmacBlindIndexer(pepper, "v1");
    SealedRegistry.init(new FakeSealer(), indexer);
    DataSource ds = new JdbcDataSource();
    ((JdbcDataSource) ds).setURL("jdbc:h2:mem:sealq2" + System.nanoTime() + ";DB_CLOSE_DELAY=-1");
    ((JdbcDataSource) ds).setUser("sa");
    try (Connection cn = ds.getConnection(); Statement st = cn.createStatement()) {
      st.execute("CREATE TABLE customers(id BIGINT PRIMARY KEY, email VARCHAR(255))");
      st.execute("INSERT INTO customers(id, email) VALUES (1, 'a@x.com')");
    }
    SealedConfig cfg = new SealedConfig(
        SealedConfig.SchemaMode.UPDATE, SealedMigration.STRICT, 100, false, false);
    SealedRuntime.run(ds, List.of(CustomerEntity.class), cfg, new FakeSealer(), indexer);
    try (Connection cn = ds.getConnection();
         Statement st = cn.createStatement();
         ResultSet rs = st.executeQuery("SELECT email_se FROM customers WHERE id=1")) {
      rs.next();
      assertTrue(rs.getString(1).startsWith("v9:"));
    }
  }
}
