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

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import javax.sql.DataSource;

/**
 * Migrador plano -&gt; sellado.
 * STRICT: job paginado al arrancar por modelo: SELECT id,legacy WHERE *_se IS NULL
 *   ORDER BY id con FOR UPDATE SKIP LOCKED opcional -&gt; seal+hash -&gt; UPDATE
 *   con re-chequeo AND *_se IS NULL. Idempotente, reanudable, multi-instancia.
 *   Paginacion portable via Statement.setMaxRows (sin LIMIT de motor).
 * LAZY: lo hace el listener por operacion read/insert/update.
 * Nunca borra la columna legacy salvo drop-legacy explicito.
 */
public final class SealedMigrator {
  private final SealedConfig config;
  private final Sealer sealer;
  private final BlindIndexer indexer;

  public SealedMigrator(SealedConfig config, Sealer sealer, BlindIndexer indexer) {
    this.config = config;
    this.sealer = sealer;
    this.indexer = indexer;
  }

  public record MigrateResult(String table, long rows, int batches) {}

  public SealedMigration effectivePolicy(SealedMigration entityPolicy) {
    if (entityPolicy == null) return config.migrationDefault();
    return entityPolicy;
  }

  public boolean isStrict(SealedMigration p) {
    return p == SealedMigration.STRICT || p == SealedMigration.STRICT_LAZY;
  }

  public boolean isLazy(SealedMigration p) {
    return p == SealedMigration.LAZY || p == SealedMigration.STRICT_LAZY;
  }

  /** Backfill STRICT de todos los modelos con politica efectiva STRICT. Todos los campos sellados por tabla. */
  public List<MigrateResult> migrateStrict(DataSource ds, List<SealedModels.EntityModel> models) throws Exception {
    SealedCodec codec = new SealedCodec(sealer, indexer);
    List<MigrateResult> out = new ArrayList<>();
    for (SealedModels.EntityModel m : models) {
      if (!isStrict(effectivePolicy(m.migration())) || m.fields().isEmpty()) continue;
      long rows = 0;
      int batches = 0;
      // Un campo sellado = un par de columnas derivadas (email_se/email_sh) con su propio
      // SELECT/UPDATE: se sella campo a campo para no mezclar dominios (AAD por campo).
      for (SealedModels.FieldModel f : m.fields()) {
        while (true) {
          List<Row> batch = selectBatch(ds, m, f);
          if (batch.isEmpty()) break;
          updateBatch(ds, m, f, batch, codec);
          rows += batch.size();
          batches++;
        }
      }
      out.add(new MigrateResult(m.table(), rows, batches));
    }
    return out;
  }

  private record Row(Object id, String legacy) {}
  private record SealRow(Object id, String legacy, String encrypt) {}

  /**
   * Re-sellado tras rotación (v1→v2): re-escribe con la versión activa las filas
   * cuyo {@code *_se} lleva prefijo distinto de {@code activeVersion}.
   * Lectura dual (RotatingSealer abre v1 y v2), escritura siempre activa.
   * Idempotente y reanudable; devuelve 0 filas cuando ya está todo en la versión activa.
   * El hash se regenera con el indexer inyectado (si rotó el pepper, usar RotatingBlindIndexer
   * y después las búsquedas con IN encuentran ambas versiones hasta re-indexar).
   */
  public List<MigrateResult> migrateReSeal(DataSource ds, List<SealedModels.EntityModel> models, String activeVersion) throws Exception {
    SealedCodec codec = new SealedCodec(sealer, indexer);
    List<MigrateResult> out = new ArrayList<>();
    for (SealedModels.EntityModel m : models) {
      if (m.fields().isEmpty()) continue;
      long rows = 0;
      int batches = 0;
      for (SealedModels.FieldModel f : m.fields()) {
        // Paginación keyset (WHERE id > ?) para visitar cada fila sellada una vez;
        // el filtro por versión se hace en Java (portable, sin LIKE de motor).
        Object lastId = null;
        while (true) {
          List<SealRow> batch = selectSealedBatchAfter(ds, m, f, lastId);
          if (batch.isEmpty()) break;
          lastId = batch.get(batch.size() - 1).id();
          List<SealRow> stale = new ArrayList<>();
          for (SealRow r : batch) {
            if (r.encrypt() == null) continue; // legacy sin sellar: lo cubre migrateStrict
            if (activeVersion.equals(SealedSupport.versionOf(r.encrypt(), ""))) continue;
            stale.add(r);
          }
          if (!stale.isEmpty()) {
            updateReSealBatch(ds, m, f, stale, codec);
            rows += stale.size();
            batches++;
          }
        }
      }
      out.add(new MigrateResult(m.table(), rows, batches));
    }
    return out;
  }

  private List<SealRow> selectSealedBatchAfter(DataSource ds, SealedModels.EntityModel m,
                                               SealedModels.FieldModel f, Object afterId) throws Exception {
    SealedCodec.Resolved cols = f.cols();
    boolean hasAfter = afterId != null;
    String sql = "SELECT " + m.idColumn() + ", " + cols.legacyCol() + ", " + cols.encryptCol() + " FROM " + m.table()
        + " WHERE " + cols.encryptCol() + " IS NOT NULL"
        + (hasAfter ? " AND " + m.idColumn() + " > ?" : "")
        + " ORDER BY " + m.idColumn();
    List<SealRow> out = new ArrayList<>();
    try (Connection cn = ds.getConnection();
         PreparedStatement ps = cn.prepareStatement(sql)) {
      if (hasAfter) ps.setObject(1, afterId);
      ps.setMaxRows(Math.max(1, config.batchSize()));
      try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) out.add(new SealRow(rs.getObject(1), rs.getString(2), rs.getString(3)));
      }
    }
    return out;
  }

  private List<SealRow> selectSealedBatch(DataSource ds, SealedModels.EntityModel m, SealedModels.FieldModel f) throws Exception {
    return selectSealedBatchAfter(ds, m, f, null);
  }

  private void updateReSealBatch(DataSource ds, SealedModels.EntityModel m, SealedModels.FieldModel f,
                                 List<SealRow> batch, SealedCodec codec) throws Exception {
    SealedCodec.Resolved cols = f.cols();
    boolean searchable = cols.hashCol() != null;
    String sql = "UPDATE " + m.table() + " SET " + cols.encryptCol() + " = ?"
        + (searchable ? ", " + cols.hashCol() + " = ?" : "")
        + " WHERE " + m.idColumn() + " = ?";
    try (Connection cn = ds.getConnection();
         PreparedStatement ps = cn.prepareStatement(sql)) {
      for (SealRow r : batch) {
        // Plano vía dual-read (abre v1 y v2) o fallback legacy
        String plain = codec.fromColumns(r.legacy(), r.encrypt(), f.ann().domain());
        if (plain == null) continue;
        SealedCodec.EncHash eh = codec.toColumns(plain, f.ann().domain(), searchable);
        int i = 1;
        ps.setString(i++, eh.encrypt());
        if (searchable) ps.setString(i++, eh.hash());
        ps.setObject(i, r.id());
        ps.addBatch();
      }
      ps.executeBatch();
    }
  }

  /**
   * Purga explícita de la columna legacy ({@code drop-legacy: true}).
   * Solo elimina la columna {@code legacy} de un campo si TODAS las filas con
   * legacy no nulo ya tienen {@code *_se} sellado (backfill completo), para no
   * perder datos en claro. Idempotente: si la columna ya no existe, no hace nada.
   * <p>El DROP lo ejecuta el reconciliador; este método decide el "cuándo" seguro.
   */
  public List<DropResult> dropLegacyColumns(DataSource ds, List<SealedModels.EntityModel> models) throws Exception {
    List<DropResult> out = new ArrayList<>();
    if (!config.dropLegacy()) return out; // gated: solo si drop-legacy=true
    for (SealedModels.EntityModel m : models) {
      for (SealedModels.FieldModel f : m.fields()) {
        SealedCodec.Resolved cols = f.cols();
        if (!hasColumn(ds, m.table(), cols.legacyCol())) continue;
        long pending = countUnsealedLegacy(ds, m, f);
        if (pending > 0) {
          out.add(new DropResult(m.table(), cols.legacyCol(), false, pending));
          continue;
        }
        try (Connection cn = ds.getConnection(); var st = cn.createStatement()) {
          st.execute("ALTER TABLE " + m.table() + " DROP COLUMN " + cols.legacyCol());
        }
        out.add(new DropResult(m.table(), cols.legacyCol(), true, 0));
      }
    }
    return out;
  }

  private long countUnsealedLegacy(DataSource ds, SealedModels.EntityModel m, SealedModels.FieldModel f) throws Exception {
    SealedCodec.Resolved cols = f.cols();
    String sql = "SELECT COUNT(*) FROM " + m.table()
        + " WHERE " + cols.legacyCol() + " IS NOT NULL AND " + cols.encryptCol() + " IS NULL";
    try (Connection cn = ds.getConnection();
         PreparedStatement ps = cn.prepareStatement(sql);
         ResultSet rs = ps.executeQuery()) {
      return rs.next() ? rs.getLong(1) : 0L;
    }
  }

  private static boolean hasColumn(DataSource ds, String table, String column) throws Exception {
    try (Connection cn = ds.getConnection()) {
      return SealedSchemaReconciler.hasColumn(cn.getMetaData(), table, column);
    }
  }

  /** Resultado de purga por campo: {@code dropped=false} si quedaban filas sin sellar. */
  public record DropResult(String table, String legacyColumn, boolean dropped, long unsealedRows) {}

  private List<Row> selectBatch(DataSource ds, SealedModels.EntityModel m, SealedModels.FieldModel f) throws Exception {
    SealedCodec.Resolved cols = f.cols();
    String sql = "SELECT " + m.idColumn() + ", " + cols.legacyCol() + " FROM " + m.table()
        + " WHERE " + cols.encryptCol() + " IS NULL AND " + cols.legacyCol() + " IS NOT NULL"
        + " ORDER BY " + m.idColumn()
        + (config.strictLocking() ? " FOR UPDATE SKIP LOCKED" : "");
    List<Row> out = new ArrayList<>();
    try (Connection cn = ds.getConnection();
         PreparedStatement ps = cn.prepareStatement(sql)) {
      ps.setMaxRows(Math.max(1, config.batchSize()));
      try (ResultSet rs = ps.executeQuery()) {
        while (rs.next()) out.add(new Row(rs.getObject(1), rs.getString(2)));
      }
    }
    return out;
  }

  private void updateBatch(DataSource ds, SealedModels.EntityModel m, SealedModels.FieldModel f,
                           List<Row> batch, SealedCodec codec) throws Exception {
    SealedCodec.Resolved cols = f.cols();
    boolean searchable = cols.hashCol() != null;
    // Re-chequeo AND *_se IS NULL para idempotencia entre replicas.
    String sql = "UPDATE " + m.table() + " SET " + cols.encryptCol() + " = ?"
        + (searchable ? ", " + cols.hashCol() + " = ?" : "")
        + " WHERE " + m.idColumn() + " = ? AND " + cols.encryptCol() + " IS NULL";
    try (Connection cn = ds.getConnection();
         PreparedStatement ps = cn.prepareStatement(sql)) {
      for (Row r : batch) {
        SealedCodec.EncHash eh = codec.toColumns(r.legacy(), f.ann().domain(), searchable);
        int i = 1;
        ps.setString(i++, eh.encrypt());
        if (searchable) ps.setString(i++, eh.hash());
        ps.setObject(i, r.id());
        ps.addBatch();
      }
      ps.executeBatch();
    }
  }
}
