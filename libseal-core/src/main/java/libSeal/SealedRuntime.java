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

import java.util.List;
import javax.sql.DataSource;

/**
 * Orquestador de arranque comun a todos los frameworks. Ejecuta en orden:
 * <ol>
 *   <li>{@link SealedRegistry#init} — registra sealer/indexer para los tipos Hibernate;</li>
 *   <li>reconcile DDL (crea columnas/indices que falten segun {@code schema-mode});</li>
 *   <li>backfill STRICT de los modelos con politica efectiva STRICT;</li>
 *   <li>purga de columna legacy si {@code drop-legacy=true} y el backfill esta completo.</li>
 * </ol>
 * Quarkus ({@code SealedBootstrap}) y Spring ({@code SealedSpringAutoConfiguration})
 * delegan aqui: una sola implementacion, un solo comportamiento.
 */
public final class SealedRuntime {
  private SealedRuntime() {}

  public record RunResult(List<String> appliedDdl,
                          List<SealedMigrator.MigrateResult> migrated,
                          List<SealedMigrator.DropResult> dropped) {}

  public static RunResult run(DataSource ds, List<Class<?>> entities, SealedConfig config,
                              Sealer sealer, BlindIndexer indexer) throws Exception {
    SealedRegistry.init(sealer, indexer);
    List<SealedModels.EntityModel> models = SealedModels.scan(entities);
    if (models.isEmpty()) return new RunResult(List.of(), List.of(), List.of());

    // LAZY: registra el resellador (UPDATE explicito) para que reading una fila
    // heredada la selle en el acto. Se hace aqui para que Quarkus/Spring lo obtengan
    // con una sola llamada y sin divergencias entre ramas.
    SealedRegistry.initDirtyMarker(new SealedResealer(ds, config, sealer, indexer, models).marker());

    SealedSchemaReconciler rec = new SealedSchemaReconciler(ds, config);
    SealedSchemaReconciler.ReconcileResult reconciled =
        rec.reconcileAll(SealedModels.toReconciler(models));

    SealedMigrator migrator = new SealedMigrator(config, sealer, indexer);
    List<SealedMigrator.MigrateResult> migrated = migrator.migrateStrict(ds, models);
    List<SealedMigrator.DropResult> dropped = migrator.dropLegacyColumns(ds, models);
    return new RunResult(reconciled.applied(), migrated, dropped);
  }

  /**
   * Genera el contenido Flyway del DDL pendiente sin aplicarlo (schema-mode agnostico).
   * El glue lo escribe en {@code seal.export-path} al arrancar si esta configurado.
   * Devuelve solo la cabecera si no hay DDL pendiente.
   */
  public static String exportFlyway(DataSource ds, List<Class<?>> entities, SealedConfig config) throws Exception {
    List<SealedModels.EntityModel> models = SealedModels.scan(entities);
    SealedSchemaReconciler rec = new SealedSchemaReconciler(ds, config);
    return rec.exportFlyway(SealedModels.toReconciler(models));
  }
}