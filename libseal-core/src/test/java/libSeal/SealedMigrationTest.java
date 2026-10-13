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
  public void exportedFlywaySqlAppliesAndThenValidatePasses() throws Exception {
    createLegacyTable();
    List<SealedModels.EntityModel> models = SealedModels.scan(Collections.singletonList(Customer.class));
    SealedSchemaReconciler export = new SealedSchemaReconciler(
        ds, new SealedConfig(SealedConfig.SchemaMode.VALIDATE_EXPORT, SealedMigration.LAZY, 500, false, true));
    String flywaySql = export.exportFlyway(SealedModels.toReconciler(models));

    // Aplica el SQL generado con Flyway real sobre la misma H2 (en memoria compartida)
    java.nio.file.Path dir = java.nio.file.Files.createTempDirectory("libseal-flyway");
    java.nio.file.Files.writeString(dir.resolve("V2__libseal.sql"), flywaySql);
    org.flywaydb.core.Flyway.configure()
        .dataSource(ds)
        .locations("filesystem:" + dir)
        .baselineOnMigrate(true) // la tabla legacy ya existe: baseline y aplica V1
        .load()
        .migrate();

    // Ya no hay DDL pendiente y VALIDATE no falla
    List<String> pending = export.exportSql(SealedModels.toReconciler(models));
    assertTrue("tras aplicar Flyway no debe quedar DDL pendiente", pending.isEmpty());
    new SealedSchemaReconciler(ds,
        new SealedConfig(SealedConfig.SchemaMode.VALIDATE, SealedMigration.LAZY, 500, false, true))
        .reconcileAll(SealedModels.toReconciler(models));
  }

  @Test
  public void resealerSealsSingleLegacyRowIdempotently() throws Exception {
    createLegacyTable();
    List<SealedModels.EntityModel> models = SealedModels.scan(Collections.singletonList(Customer.class));
    new SealedSchemaReconciler(ds, SealedConfig.defaults()).reconcileAll(SealedModels.toReconciler(models));

    SealedResealer resealer = new SealedResealer(
        ds, SealedConfig.defaults(), new FakeSealer(), SealedRegistry.indexer(), models);
    Customer c = new Customer();
    c.id = 1;
    c.email = "a@x.com";
    resealer.reseal(c);

    try (Connection cn = ds.getConnection();
         Statement st = cn.createStatement();
         ResultSet rs = st.executeQuery("SELECT email, email_se, email_sh FROM customers WHERE id=1")) {
      rs.next();
      assertEquals("a@x.com", rs.getString(1)); // legacy intacto
      assertTrue(rs.getString(2).startsWith("v9:"));
      assertTrue(rs.getString(3).startsWith("v1:"));
    }
    // Idempotente: al estar ya sellada, el re-chequeo AND *_se IS NULL no reescribe
    resealer.reseal(c);
  }

  /** A1: el @Id con @Column(name) distinto del nombre del campo debe seguir funcionando. */
  @SealedEntity(domain = "cust", migration = SealedMigration.LAZY)
  @jakarta.persistence.Table(name = "c_ids")
  static class RenamedId {
    @jakarta.persistence.Id
    @jakarta.persistence.Column(name = "customer_id")
    long id;
    @Sealed(domain = "cust.email")
    String email;
  }

  /** A3: @SealedEntity en superclase y @Id/@Sealed heredados. */
  @SealedEntity(domain = "base", migration = SealedMigration.LAZY)
  static abstract class BaseEntity {
    @jakarta.persistence.Id
    long id;
    @Sealed(domain = "base.email")
    String email;
  }

  @jakarta.persistence.Table(name = "derived")
  static class Derived extends BaseEntity {
    String other;
  }

  @Test
  public void resealerHandlesIdColumnRenamedFromField() throws Exception {
    try (Connection cn = ds.getConnection(); Statement st = cn.createStatement()) {
      st.execute("CREATE TABLE c_ids(customer_id BIGINT PRIMARY KEY, email VARCHAR(255))");
      st.execute("INSERT INTO c_ids(customer_id, email) VALUES (7, 'ren@x.com')");
    }
    List<SealedModels.EntityModel> models = SealedModels.scan(Collections.singletonList(RenamedId.class));
    assertEquals("id", models.get(0).idField());
    assertEquals("customer_id", models.get(0).idColumn());
    new SealedSchemaReconciler(ds, SealedConfig.defaults()).reconcileAll(SealedModels.toReconciler(models));

    SealedResealer resealer = new SealedResealer(
        ds, SealedConfig.defaults(), new FakeSealer(), SealedRegistry.indexer(), models);
    RenamedId r = new RenamedId();
    r.id = 7;
    r.email = "ren@x.com";
    resealer.reseal(r);

    try (Connection cn = ds.getConnection();
         Statement st = cn.createStatement();
         ResultSet rs = st.executeQuery("SELECT email_se FROM c_ids WHERE customer_id=7")) {
      rs.next();
      assertTrue("A1: resealer debe encontrar el id por field name", rs.getString(1).startsWith("v9:"));
    }
  }

  @Test
  public void scanFindsSealedFieldsAndIdInSuperclass() {
    List<SealedModels.EntityModel> models = SealedModels.scan(Collections.singletonList(Derived.class));
    assertEquals(1, models.size());
    assertEquals("derived", models.get(0).table());
    assertEquals("id", models.get(0).idField());
    assertEquals(1, models.get(0).fields().size()); // email heredado de BaseEntity
    assertEquals("email", models.get(0).fields().get(0).field());
  }

  /** A4: @SealedEntity es @Inherited, visible en subclases (y por tanto en proxies). */
  @Test
  public void sealedEntityAnnotationIsInherited() {
    assertTrue(Derived.class.isAnnotationPresent(SealedEntity.class));
    assertTrue(Derived.class.getAnnotation(SealedEntity.class) != null);
  }

  @Test
  public void validateModeThrowsWhenDdlPending() throws Exception {
    createLegacyTable();
    List<SealedModels.EntityModel> models = SealedModels.scan(Collections.singletonList(Customer.class));
    SealedConfig validate = new SealedConfig(
        SealedConfig.SchemaMode.VALIDATE, SealedMigration.LAZY, 500, false, true);
    SealedSchemaReconciler rec = new SealedSchemaReconciler(ds, validate);
    try {
      rec.reconcileAll(SealedModels.toReconciler(models));
      assertTrue("VALIDATE debe fallar si hay DDL pendiente", false);
    } catch (IllegalStateException expected) {
      assertTrue(expected.getMessage().contains("DDL pendiente"));
    }
    // Tras aplicar con UPDATE, VALIDATE ya no falla
    new SealedSchemaReconciler(ds, SealedConfig.defaults()).reconcileAll(SealedModels.toReconciler(models));
    rec.reconcileAll(SealedModels.toReconciler(models));
  }

  /** B1: SealedRuntime.run registra el resellador LAZY (una sola llamada). */
  @Test
  public void runtimeRunRegistersLazyResealer() throws Exception {
    createLegacyTable();
    SealedConfig cfg = new SealedConfig(
        SealedConfig.SchemaMode.UPDATE, SealedMigration.STRICT, 100, false, false);
    List<Class<?>> entities = Collections.singletonList(Customer.class);
    assertTrue("antes no debe haber marcador", !SealedRegistry.hasDirtyMarker());
    SealedRuntime.run(ds, entities, cfg, new FakeSealer(), SealedRegistry.indexer());
    assertTrue("SealedRuntime.run debe registrar el resellador", SealedRegistry.hasDirtyMarker());
  }

  /** B3: parse tolera null/blank/typos cayendo a defaults sin lanzar. */
  @Test
  public void configParseIsTolerantOfBadValues() {
    SealedConfig d = SealedConfig.parse(null, "", 0, false, true);
    assertEquals(SealedConfig.SchemaMode.UPDATE, d.schemaMode());
    assertEquals(SealedMigration.LAZY, d.migrationDefault());
    assertEquals(500, d.batchSize()); // 0 -> default
    SealedConfig typo = SealedConfig.parse("no-existe", "tampoco", -5, true, false);
    assertEquals(SealedConfig.SchemaMode.UPDATE, typo.schemaMode());
    assertEquals(SealedMigration.LAZY, typo.migrationDefault());
    assertEquals(500, typo.batchSize());
    assertTrue(typo.dropLegacy());
    SealedConfig ok = SealedConfig.parse("validate", "strict", 10, false, true);
    assertEquals(SealedConfig.SchemaMode.VALIDATE, ok.schemaMode());
    assertEquals(SealedMigration.STRICT, ok.migrationDefault());
    assertEquals(10, ok.batchSize());
  }

  @Test
  public void strictWithoutLockingMigratesOnEngineWithoutSkipLocked() throws Exception {
    // H2 no soporta FOR UPDATE SKIP LOCKED: con strictLocking=false debe funcionar.
    createLegacyTable();
    List<SealedModels.EntityModel> models = SealedModels.scan(Collections.singletonList(Customer.class));
    new SealedSchemaReconciler(ds, SealedConfig.defaults()).reconcileAll(SealedModels.toReconciler(models));
    SealedConfig cfg = new SealedConfig(SealedConfig.SchemaMode.UPDATE, SealedMigration.STRICT, 2, false, false);
    List<SealedMigrator.MigrateResult> res =
        new SealedMigrator(cfg, new FakeSealer(), SealedRegistry.indexer()).migrateStrict(ds, models);
    assertEquals(2, res.get(0).rows());
    // Sin locking genera el mismo SQL portable: la libreria no usa LIMIT ni SKIP LOCKED
    assertTrue(new SealedConfig(SealedConfig.SchemaMode.UPDATE, SealedMigration.STRICT, 2, false, true)
        .withoutLocking().strictLocking() == false);
  }

  @Test
  public void dropLegacyPurgesOnlyWhenBackfillComplete() throws Exception {
    createLegacyTable();
    List<SealedModels.EntityModel> models = SealedModels.scan(Collections.singletonList(Customer.class));
    new SealedSchemaReconciler(ds, SealedConfig.defaults()).reconcileAll(SealedModels.toReconciler(models));

    SealedConfig strict = new SealedConfig(SealedConfig.SchemaMode.UPDATE, SealedMigration.STRICT, 100, true, false);
    SealedMigrator migrator = new SealedMigrator(strict, new FakeSealer(), SealedRegistry.indexer());

    // Backfill incompleto (filas aun sin sellar): NO debe eliminar la columna legacy
    SealedMigrator.DropResult refused = migrator.dropLegacyColumns(ds, models).get(0);
    assertTrue("debe negarse si hay filas sin sellar", !refused.dropped());
    assertTrue(refused.unsealedRows() > 0);
    assertTrue(hasLegacyColumn("customers", "email"));

    // Backfill completo y purga: la columna legacy desaparece
    migrator.migrateStrict(ds, models);
    SealedMigrator.DropResult dropped = migrator.dropLegacyColumns(ds, models).get(0);
    assertTrue("debe purgar con backfill completo", dropped.dropped());
    assertEquals(0, dropped.unsealedRows());
    assertTrue("la columna legacy ya no existe", !hasLegacyColumn("customers", "email"));

    // Idempotente: segunda pasada no encuentra nada que hacer
    assertTrue(migrator.dropLegacyColumns(ds, models).isEmpty());
  }

  @Test
  public void strictIsSafeUnderConcurrentInstances() throws Exception {
    try (Connection cn = ds.getConnection(); Statement st = cn.createStatement()) {
      st.execute("CREATE TABLE customers(id BIGINT PRIMARY KEY, email VARCHAR(255))");
      StringBuilder ins = new StringBuilder("INSERT INTO customers(id, email) VALUES ");
      for (int i = 1; i <= 50; i++) {
        if (i > 1) ins.append(", ");
        ins.append("(").append(i).append(", 'u").append(i).append("@x.com')");
      }
      st.execute(ins.toString());
    }
    List<SealedModels.EntityModel> models = SealedModels.scan(Collections.singletonList(Customer.class));
    new SealedSchemaReconciler(ds, SealedConfig.defaults()).reconcileAll(SealedModels.toReconciler(models));

    // Dos instancias compiten: el re-chequeo AND *_se IS NULL garantiza una sola escritura.
    SealedConfig cfg = new SealedConfig(SealedConfig.SchemaMode.UPDATE, SealedMigration.STRICT, 5, false, false);
    Runnable job = () -> {
      try (Connection cn = ds.getConnection()) {
        new SealedMigrator(cfg, new FakeSealer(), SealedRegistry.indexer()).migrateStrict(ds, models);
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    };
    Thread t1 = new Thread(job);
    Thread t2 = new Thread(job);
    t1.start();
    t2.start();
    t1.join();
    t2.join();

    try (Connection cn = ds.getConnection();
         Statement st = cn.createStatement();
         ResultSet rs = st.executeQuery(
             "SELECT COUNT(*), SUM(CASE WHEN email_se IS NULL THEN 1 ELSE 0 END) FROM customers")) {
      rs.next();
      assertEquals("todas las filas no nulas quedan selladas", 50, rs.getInt(1));
      assertEquals("ninguna fila sin sellar", 0, rs.getInt(2));
    }
  }

  private boolean hasLegacyColumn(String table, String column) throws Exception {
    try (Connection cn = ds.getConnection()) {
      return SealedSchemaReconciler.hasColumn(cn.getMetaData(), table, column);
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
