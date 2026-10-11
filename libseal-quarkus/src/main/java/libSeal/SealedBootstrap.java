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

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import javax.sql.DataSource;

/**
 * Bootstrap Quarkus (DB-only). Se ejecuta en StartupEvent:
 * 1. reconcile DDL por modelo/tabla, 2. strict backfill si toca.
 * En Spring Boot el equivalente es un ApplicationRunner con el mismo reconciler+migrator.
 */
// import io.quarkus.runtime.StartupEvent; // descomentar en app real
@ApplicationScoped
public class SealedBootstrap {

  @Inject DataSource dataSource;
  @Inject Sealer sealer;
  @Inject BlindIndexer indexer;

  // void onStart(@Observes StartupEvent e) throws Exception {
  //   SealedConfig cfg = SealedConfig.defaults(); // + SmallRye Config: seal.*
  //   SealedSchemaReconciler rec = new SealedSchemaReconciler(dataSource, cfg);
  //   rec.reconcileAll(SealedModels.scan());
  //   // if strict -> new SealedMigrator(cfg, sealer, indexer).migrateAllStrict();
  // }
}
