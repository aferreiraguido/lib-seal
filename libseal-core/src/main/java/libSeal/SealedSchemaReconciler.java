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
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import javax.sql.DataSource;

/**
 * Reconciliador DDL agnostico de motor (JDBC DatabaseMetaData).
 * Por cada modelo verifica y solo genera ADD COLUMN / ADD INDEX.
 * Nunca DROP ni ALTER TYPE en auto.
 * Modos: UPDATE ejecuta, VALIDATE falla si hay pendiente,
 * VALIDATE_EXPORT devuelve el pendiente sin ejecutar (para Flyway/Liquibase).
 */
public final class SealedSchemaReconciler {
  private final DataSource ds;
  private final SealedConfig config;

  public SealedSchemaReconciler(DataSource ds, SealedConfig config) {
    this.ds = ds;
    this.config = config;
  }

  /** Resultado para logs/auditoria. */
  public record ReconcileResult(List<String> applied, List<String> pending) {}

  public ReconcileResult reconcileAll(List<SealedModel> models) throws Exception {
    List<String> applied = new ArrayList<>();
    List<String> pending = new ArrayList<>();
    try (Connection cn = ds.getConnection()) {
      DatabaseMetaData md = cn.getMetaData();
      for (SealedModel m : models) {
        for (String ddl : m.requiredDdl(md)) {
          if (config.schemaMode() == SealedConfig.SchemaMode.UPDATE) {
            try (var st = cn.createStatement()) { st.execute(ddl); }
            applied.add(ddl);
          } else {
            pending.add(ddl);
          }
        }
      }
    }
    if (config.schemaMode() == SealedConfig.SchemaMode.VALIDATE && !pending.isEmpty()) {
      throw new IllegalStateException("DDL pendiente (schema-mode=VALIDATE): " + pending);
    }
    return new ReconcileResult(applied, pending);
  }

  /** Solo calcula el DDL pendiente sin ejecutar ni fallar. Para generar migraciones Flyway. */
  public List<String> exportSql(List<SealedModel> models) throws Exception {
    List<String> out = new ArrayList<>();
    try (Connection cn = ds.getConnection()) {
      DatabaseMetaData md = cn.getMetaData();
      for (SealedModel m : models) {
        out.addAll(m.requiredDdl(md));
      }
    }
    return out;
  }

  /**
   * Genera el contenido de un fichero Flyway versionado (p.ej. {@code V3__libseal.sql})
   * con el DDL pendiente. Cada sentencia termina en {@code ;} + salto de linea para que
   * Flyway la ejecute tal cual. Vacio (solo cabecera) si no hay pendiente.
   * Uso: {@code Files.writeString(dir.resolve("V3__libseal.sql"), reconciler.exportFlyway(models))}.
   */
  public String exportFlyway(List<SealedModel> models) throws Exception {
    List<String> pending = exportSql(models);
    StringBuilder sb = new StringBuilder();
    sb.append("-- libseal auto-generated: ADD COLUMN *_se (TEXT) + *_sh (VARCHAR(128)) + INDEX.\n");
    sb.append("-- Solo ADD, nunca DROP/ALTER. Revisar antes de aplicar.\n");
    for (String ddl : pending) {
      String s = ddl.trim();
      if (!s.endsWith(";")) s = s + ";";
      sb.append(s).append("\n");
    }
    return sb.toString();
  }

  /** Descriptor minimo por entidad/tabla, construido por scan de anotaciones al arrancar. */
  public interface SealedModel {
    String table();
    List<String> requiredDdl(DatabaseMetaData md) throws Exception;
  }

  static boolean hasColumn(DatabaseMetaData md, String table, String column) throws Exception {
    // Motores como H2/Oracle guardan identificadores sin comillas en MAYUSCULAS:
    // se prueba tal cual y en upper para ser agnostico de verdad.
    if (hasColumnExact(md, table, column)) return true;
    return hasColumnExact(md, table.toUpperCase(java.util.Locale.ROOT), column.toUpperCase(java.util.Locale.ROOT));
  }

  private static boolean hasColumnExact(DatabaseMetaData md, String table, String column) throws Exception {
    try (ResultSet rs = md.getColumns(null, null, table, column)) {
      return rs.next();
    }
  }
}
