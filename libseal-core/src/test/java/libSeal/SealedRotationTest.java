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
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.sql.DataSource;
import org.h2.jdbcx.JdbcDataSource;
import org.junit.Before;
import org.junit.Test;

/** Rotación v1→v2: dual-read del cifrado, dual-hash en búsqueda, re-sellado idempotente. */
public class SealedRotationTest {

  static final class VersionedFakeSealer implements Sealer {
    private final String version;
    VersionedFakeSealer(String version) { this.version = version; }
    @Override public String seal(String plain, String aad) {
      if (plain == null) return null;
      return version + ":" + Base64.getEncoder().encodeToString((aad + "|" + plain).getBytes(StandardCharsets.UTF_8));
    }
    @Override public String unseal(String ct, String aad) {
      String b64 = ct.substring(ct.indexOf(':') + 1);
      String s = new String(Base64.getDecoder().decode(b64), StandardCharsets.UTF_8);
      if (!s.startsWith(aad + "|")) throw new IllegalStateException("AAD mismatch");
      return s.substring(aad.length() + 1);
    }
  }

  static final class VersionedFakeIndexer implements BlindIndexer {
    private final String version;
    VersionedFakeIndexer(String version) { this.version = version; }
    @Override public String normalize(String v) { return SealedSupport.normalize(v); }
    @Override public String hash(String v, String domain) {
      if (v == null) return null;
      return version + ":H(" + domain + "|" + normalize(v) + ")";
    }
  }

  @SealedEntity(domain = "customer", migration = SealedMigration.STRICT)
  @jakarta.persistence.Table(name = "customers")
  static class Customer {
    @jakarta.persistence.Id
    long id;
    @Sealed(domain = "customer.email")
    String email;
  }

  private DataSource ds;

  @Before
  public void init() {
    JdbcDataSource h2 = new JdbcDataSource();
    h2.setURL("jdbc:h2:mem:rot" + System.nanoTime() + ";DB_CLOSE_DELAY=-1");
    h2.setUser("sa");
    ds = h2;
  }

  @Test
  public void sealerDualReadOldAndNew() {
    Map<String, Sealer> sealers = new LinkedHashMap<>();
    sealers.put("v1", new VersionedFakeSealer("v1"));
    sealers.put("v2", new VersionedFakeSealer("v2"));
    RotatingSealer rot = new RotatingSealer(sealers, "v1");
    String v1ct = rot.seal("a@x.com", "customer.email");
    assertTrue(v1ct.startsWith("v1:"));
    rot.rotateTo("v2");
    assertEquals("v2", rot.active());
    String v2ct = rot.seal("b@x.com", "customer.email");
    assertTrue(v2ct.startsWith("v2:"));
    // dual-read: ambas abren tras rotar
    assertEquals("a@x.com", rot.unseal(v1ct, "customer.email"));
    assertEquals("b@x.com", rot.unseal(v2ct, "customer.email"));
  }

  @Test
  public void indexerDualHashCoversBothPeppers() {
    Map<String, BlindIndexer> indexers = new LinkedHashMap<>();
    indexers.put("v1", new VersionedFakeIndexer("v1"));
    indexers.put("v2", new VersionedFakeIndexer("v2"));
    RotatingBlindIndexer rot = new RotatingBlindIndexer(indexers, "v2");
    List<String> hashes = rot.hashesFor("Hola@X.com ", "customer.email");
    assertEquals(2, hashes.size());
    assertTrue(hashes.get(0).startsWith("v1:"));
    assertTrue(hashes.get(1).startsWith("v2:"));
    // Normalización idéntica en ambas versiones
    assertEquals(hashes, rot.hashesFor("hola@x.com", "customer.email"));
  }

  @Test
  public void resealMigratesV1RowsToV2AndIsIdempotent() throws Exception {
    // Sellado inicial con v1
    Sealer v1 = new VersionedFakeSealer("v1");
    BlindIndexer idxV1 = new VersionedFakeIndexer("v1");
    SealedRegistry.init(v1, idxV1);
    try (Connection cn = ds.getConnection(); Statement st = cn.createStatement()) {
      st.execute("CREATE TABLE customers(id BIGINT PRIMARY KEY, email VARCHAR(255))");
      st.execute("INSERT INTO customers(id, email) VALUES (1, 'a@x.com'), (2, 'b@x.com')");
    }
    List<SealedModels.EntityModel> models = SealedModels.scan(Collections.singletonList(Customer.class));
    new SealedSchemaReconciler(ds, SealedConfig.defaults()).reconcileAll(SealedModels.toReconciler(models));
    SealedConfig cfg = new SealedConfig(SealedConfig.SchemaMode.UPDATE, SealedMigration.STRICT, 10, false, false);
    new SealedMigrator(cfg, v1, idxV1).migrateStrict(ds, models);

    // Rotación: lectura dual v1+v2, escritura v2
    Map<String, Sealer> sealers = new LinkedHashMap<>();
    sealers.put("v1", v1);
    sealers.put("v2", new VersionedFakeSealer("v2"));
    RotatingSealer rotSealer = new RotatingSealer(sealers, "v2");
    Map<String, BlindIndexer> indexers = new LinkedHashMap<>();
    indexers.put("v1", idxV1);
    indexers.put("v2", new VersionedFakeIndexer("v2"));
    RotatingBlindIndexer rotIndexer = new RotatingBlindIndexer(indexers, "v2");
    SealedRegistry.init(rotSealer, rotIndexer);

    List<SealedMigrator.MigrateResult> first =
        new SealedMigrator(cfg, rotSealer, rotIndexer).migrateReSeal(ds, models, "v2");
    assertEquals(1, first.size());
    assertEquals(2, first.get(0).rows());

    try (Connection cn = ds.getConnection();
         Statement st = cn.createStatement();
         ResultSet rs = st.executeQuery("SELECT email, email_se, email_sh FROM customers ORDER BY id")) {
      rs.next();
      assertEquals("a@x.com", rs.getString(1)); // legacy intacto
      assertTrue(rs.getString(2).startsWith("v2:"));
      assertTrue(rs.getString(3).startsWith("v2:"));
      // El plano sigue recuperable vía dual-read
      assertEquals("a@x.com", rotSealer.unseal(rs.getString(2), "customer.email"));
      rs.next();
      assertTrue(rs.getString(2).startsWith("v2:"));
    }

    List<SealedMigrator.MigrateResult> second =
        new SealedMigrator(cfg, rotSealer, rotIndexer).migrateReSeal(ds, models, "v2");
    assertEquals(0, second.get(0).rows()); // idempotente
  }
}
