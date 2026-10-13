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
import static org.junit.Assert.assertNull;
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

/** Secuencia de arranque (reconcile + backfill + purga) y registro estatico, sin contenedor. */
public class SealedBootstrapTest {

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
    byte[] pepper = new byte[32];
    java.util.Arrays.fill(pepper, (byte) 7);
    SealedRegistry.init(new FakeSealer(), new HmacBlindIndexer(pepper, "v1"));
    JdbcDataSource h2 = new JdbcDataSource();
    h2.setURL("jdbc:h2:mem:sealboot" + System.nanoTime() + ";DB_CLOSE_DELAY=-1");
    h2.setUser("sa");
    ds = h2;
  }

  @Test
  public void startupReconcilesBackfillsAndPurgesLegacy() throws Exception {
    try (Connection cn = ds.getConnection(); Statement st = cn.createStatement()) {
      st.execute("CREATE TABLE customers(id BIGINT PRIMARY KEY, email VARCHAR(255))");
      st.execute("INSERT INTO customers(id, email) VALUES (1, 'a@x.com'), (2, 'b@x.com')");
    }
    SealedConfig cfg = new SealedConfig(
        SealedConfig.SchemaMode.UPDATE, SealedMigration.STRICT, 100, true, false);
    SealedRuntime.RunResult result =
        SealedBootstrap.doStart(List.of(Customer.class), cfg, ds, new FakeSealer(), SealedRegistry.indexer());

    assertEquals(3, result.appliedDdl().size());            // ADD se + ADD sh + INDEX
    assertEquals(2, result.migrated().get(0).rows());       // ambos sellados
    assertTrue(result.dropped().get(0).dropped());          // legacy purgado (backfill completo)

    try (Connection cn = ds.getConnection(); Statement st = cn.createStatement()) {
      try (ResultSet rs = st.executeQuery("SELECT email_se, email_sh FROM customers ORDER BY id")) {
        assertTrue(rs.next());
        assertTrue(rs.getString(1).startsWith("v9:"));
        assertTrue(rs.getString(2).startsWith("v1:"));
      }
      // La columna legacy ya no existe
      SealedSchemaReconciler rec = new SealedSchemaReconciler(ds, cfg);
      assertTrue(!rec.exportSql(SealedModels.toReconciler(
          SealedModels.scan(List.of(Customer.class)))).isEmpty() == false);
    }
  }

  @Test
  public void startupWithNoEntitiesIsNoOp() throws Exception {
    SealedRuntime.RunResult result = SealedBootstrap.doStart(
        List.of(), SealedConfig.defaults(), ds, new FakeSealer(), SealedRegistry.indexer());
    assertTrue(result.appliedDdl().isEmpty());
    assertTrue(result.migrated().isEmpty());
  }

  @Test
  public void initializerExposesConfiguredPrimitives() {
    byte[] pepper = new byte[32];
    java.util.Arrays.fill(pepper, (byte) 5);
    Sealer s = new FakeSealer();
    BlindIndexer i = new HmacBlindIndexer(pepper, "v1");
    SealedRegistry.init(s, i);
    assertTrue(SealedRegistry.sealer() == s);
    assertTrue(SealedRegistry.indexer() == i);
  }

  @Test
  public void nullEmailStaysNull() throws Exception {
    try (Connection cn = ds.getConnection(); Statement st = cn.createStatement()) {
      st.execute("CREATE TABLE customers(id BIGINT PRIMARY KEY, email VARCHAR(255))");
      st.execute("INSERT INTO customers(id, email) VALUES (1, NULL)");
    }
    SealedConfig cfg = new SealedConfig(
        SealedConfig.SchemaMode.UPDATE, SealedMigration.STRICT, 100, false, false);
    SealedRuntime.RunResult result =
        SealedBootstrap.doStart(List.of(Customer.class), cfg, ds, new FakeSealer(), SealedRegistry.indexer());
    assertEquals(0, result.migrated().get(0).rows()); // NULL no migra
    try (Connection cn = ds.getConnection();
         Statement st = cn.createStatement();
         ResultSet rs = st.executeQuery("SELECT email_se FROM customers WHERE id=1")) {
      rs.next();
      assertNull(rs.getString(1));
    }
  }
}