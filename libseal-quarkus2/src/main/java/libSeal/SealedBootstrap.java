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

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.inject.Inject;
import javax.sql.DataSource;

/**
 * Bootstrap Quarkus 2.13 (DB-only, javax). Se ejecuta en StartupEvent:
 * 1. reconcile DDL por modelo/tabla, 2. strict backfill si toca.
 */
@ApplicationScoped
public class SealedBootstrap {

  @Inject DataSource dataSource;
  @Inject Sealer sealer;
  @Inject BlindIndexer indexer;

  // void onStart(@Observes io.quarkus.runtime.StartupEvent e) throws Exception {
  //   SealedConfig cfg = SealedConfig.defaults(); // + SmallRye Config: seal.*
  //   SealedSchemaReconciler rec = new SealedSchemaReconciler(dataSource, cfg);
  //   rec.reconcileAll(SealedModels.scan(java.util.Collections.emptyList()));
  //   // if strict -> new SealedMigrator(cfg, sealer, indexer).migrateAllStrict();
  // }
}
