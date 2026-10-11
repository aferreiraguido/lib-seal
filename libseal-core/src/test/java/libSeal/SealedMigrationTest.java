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
import java.util.Collections;
import java.util.List;
import javax.sql.DataSource;
import org.h2.jdbcx.JdbcDataSource;
import org.junit.Before;
import org.junit.Test;

/** STRICT sobre H2 real (sin SKIP LOCKED: H2 no lo soporta) + reconciliador/export. */
public class SealedMigrationTest {

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

  @SealedEntity(domain = "customer", migration = SealedMigration.STRICT)
  @jakarta.persistence.Table(name = "contacts")
  static class Contact {
    @jakarta.persistence.Id
    long id;
    @Sealed(domain = "contact.email")
    String email;
    @Sealed(domain = "contact.nif", searchable = false)
    String nif;
  }

  private DataSource ds;
  private SealedCodec codec;

  @Before
  public void init() {
    byte[] pepper = new byte[32];
    java.util.Arrays.fill(pepper, (byte) 7);
    BlindIndexer indexer = new HmacBlindIndexer(pepper, "v1");
    codec = new SealedCodec(new FakeSealer(), indexer);
    SealedRegistry.init(new FakeSealer(), indexer);
    JdbcDataSource h2 = new JdbcDataSource();
    h2.setURL("jdbc:h2:mem:seal" + System.nanoTime() + ";DB_CLOSE_DELAY=-1");
    h2.setUser("sa");
    ds = h2;
  }

  private void createLegacyTable() throws Exception {
    try (Connection cn = ds.getConnection(); Statement st = cn.createStatement()) {
      st.execute("CREATE TABLE customers(id BIGINT PRIMARY KEY, email VARCHAR(255))");
      st.execute("INSERT INTO customers(id, email) VALUES (1, 'a@x.com'), (2, 'b@x.com'), (3, NULL)");
    }
  }

  @Test
  public void reconcilerExportsAndApplies() throws Exception {
    createLegacyTable();
    List<SealedModels.EntityModel> models = SealedModels.scan(Collections.singletonList(Customer.class));
    SealedSchemaReconciler rec = new SealedSchemaReconciler(ds, SealedConfig.defaults());
    List<String> pending = rec.exportSql(SealedModels.toReconciler(models));
    assertEquals(3, pending.size()); // ADD encrypt, ADD hash, CREATE INDEX
    assertTrue(pending.get(0).contains("email_se"));
    SealedSchemaReconciler.ReconcileResult r = rec.reconcileAll(SealedModels.toReconciler(models));
    assertEquals(3, r.applied().size());
    assertTrue(rec.exportSql(SealedModels.toReconciler(models)).isEmpty());
  }

  @Test
  public void strictMigratesOnlyLegacyRowsAndIsIdempotent() throws Exception {
    createLegacyTable();
    List<SealedModels.EntityModel> models = SealedModels.scan(Collections.singletonList(Customer.class));
    new SealedSchemaReconciler(ds, SealedConfig.defaults()).reconcileAll(SealedModels.toReconciler(models));

    SealedConfig cfg = new SealedConfig(SealedConfig.SchemaMode.UPDATE, SealedMigration.STRICT, 2, false, false);
    SealedMigrator migrator = new SealedMigrator(cfg, new FakeSealer(), SealedRegistry.indexer());

    List<SealedMigrator.MigrateResult> first = migrator.migrateStrict(ds, models);
    assertEquals(1, first.size());
    assertEquals(2, first.get(0).rows()); // id 3 es NULL, no migra
    assertEquals(1, first.get(0).batches()); // batchSize=2 -> 1 lote... (2 filas en 1 lote)

    try (Connection cn = ds.getConnection();
         Statement st = cn.createStatement();
         ResultSet rs = st.executeQuery("SELECT email, email_se, email_sh FROM customers ORDER BY id")) {
      rs.next();
      assertEquals("a@x.com", rs.getString(1)); // legacy intacto
      assertTrue(rs.getString(2).startsWith("v9:"));
      assertTrue(rs.getString(3).startsWith("v1:"));
      rs.next();
      assertTrue(rs.getString(2).startsWith("v9:"));
      rs.next();
      assertNull(rs.getString(2)); // NULL no migra
    }

    List<SealedMigrator.MigrateResult> second = migrator.migrateStrict(ds, models);
    assertEquals(0, second.get(0).rows()); // idempotente
  }

  @Test
  public void strictMigratesAllSealedFieldsPerTable() throws Exception {
    try (Connection cn = ds.getConnection(); Statement st = cn.createStatement()) {
      st.execute("CREATE TABLE contacts(id BIGINT PRIMARY KEY, email VARCHAR(255), nif VARCHAR(255))");
      st.execute("INSERT INTO contacts(id, email, nif) VALUES (1, 'a@x.com', '123'), (2, NULL, '456')");
    }
    List<SealedModels.EntityModel> models = SealedModels.scan(Collections.singletonList(Contact.class));
    SealedSchemaReconciler rec = new SealedSchemaReconciler(ds, SealedConfig.defaults());
    List<String> pending = rec.exportSql(SealedModels.toReconciler(models));
    // email: ADD se + ADD sh + INDEX (3); nif no-searchable: solo ADD se (1)
    assertEquals(4, pending.size());
    assertTrue(pending.stream().anyMatch(s -> s.contains("email_se")));
    assertTrue(pending.stream().anyMatch(s -> s.contains("email_sh")));
    assertTrue(pending.stream().anyMatch(s -> s.contains("nif_se")));
    rec.reconcileAll(SealedModels.toReconciler(models));

    SealedConfig cfg = new SealedConfig(SealedConfig.SchemaMode.UPDATE, SealedMigration.STRICT, 10, false, false);
    List<SealedMigrator.MigrateResult> res =
        new SealedMigrator(cfg, new FakeSealer(), SealedRegistry.indexer()).migrateStrict(ds, models);
    assertEquals(1, res.size());
    assertEquals(3, res.get(0).rows()); // email:1 fila + nif:2 filas (dominios distintos, sello por campo)

    try (Connection cn = ds.getConnection();
         Statement st = cn.createStatement();
         ResultSet rs = st.executeQuery("SELECT email, email_se, email_sh, nif, nif_se FROM contacts ORDER BY id")) {
      rs.next();
      assertEquals("a@x.com", rs.getString(1));
      assertTrue(rs.getString(2).startsWith("v9:"));
      assertTrue(rs.getString(3).startsWith("v1:"));
      assertEquals("123", rs.getString(4));
      assertTrue(rs.getString(5).startsWith("v9:"));
      rs.next();
      assertNull(rs.getString(2)); // email NULL no migra...
      assertNull(rs.getString(3));
      assertEquals("456", rs.getString(4));
      assertTrue(rs.getString(5).startsWith("v9:")); // ...pero nif sí
    }
  }

  @Test
  public void exportFlywayIsDeterministicAndSemicolonTerminated() throws Exception {
    createLegacyTable();
    List<SealedModels.EntityModel> models = SealedModels.scan(Collections.singletonList(Customer.class));
    SealedSchemaReconciler rec = new SealedSchemaReconciler(
        ds, new SealedConfig(SealedConfig.SchemaMode.VALIDATE_EXPORT, SealedMigration.LAZY, 500, false, true));
    String flyway = rec.exportFlyway(SealedModels.toReconciler(models));
    assertTrue(flyway.startsWith("-- libseal"));
    assertTrue(flyway.contains("email_se"));
    assertTrue(flyway.contains("email_sh"));
    for (String line : flyway.split("\n")) {
      if (line.startsWith("--") || line.isBlank()) continue;
      assertTrue("cada sentencia termina en ;: " + line, line.trim().endsWith(";"));
    }
    // Tras aplicar no hay pendiente: solo queda la cabecera
    new SealedSchemaReconciler(ds, SealedConfig.defaults()).reconcileAll(SealedModels.toReconciler(models));
    String empty = rec.exportFlyway(SealedModels.toReconciler(models));
    assertTrue(empty.startsWith("-- libseal"));
    assertTrue(empty.lines().filter(l -> !l.startsWith("--") && !l.isBlank()).findAny().isEmpty());
  }
}
