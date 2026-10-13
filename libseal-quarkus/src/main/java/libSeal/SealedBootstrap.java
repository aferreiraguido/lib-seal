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

import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import java.util.ArrayList;
import java.util.List;
import javax.sql.DataSource;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Bootstrap Quarkus (DB-only). En {@link StartupEvent} ejecuta la secuencia comun
 * {@link SealedRuntime#run}: registra sealer/indexer, reconcilia DDL, backfill STRICT
 * y purga legacy si {@code seal.drop-legacy=true}.
 *
 * <p>Props {@code seal.*} via MicroProfile Config. La app aporta los beans
 * {@link Sealer}, {@link BlindIndexer} y una o mas implementaciones de
 * {@link SealedEntitySource} con las clases {@code @SealedEntity}.
 */
@ApplicationScoped
public class SealedBootstrap {

  private static final Logger LOG = LoggerFactory.getLogger(SealedBootstrap.class);

  @Inject DataSource dataSource;
  @Inject Sealer sealer;
  @Inject BlindIndexer indexer;
  @Inject Instance<SealedEntitySource> entitySources;

  void onStart(@Observes StartupEvent ev) throws Exception {
    List<Class<?>> entities = new ArrayList<>();
    for (SealedEntitySource src : entitySources) {
      List<Class<?>> es = src.sealedEntities();
      if (es != null) entities.addAll(es);
    }
    if (entities.isEmpty()) {
      LOG.debug("libseal: sin SealedEntitySource; skip reconcile/backfill");
      return;
    }

    Config cfg = ConfigProvider.getConfig();
    SealedConfig config = SealedConfig.parse(
        cfg.getOptionalValue("seal.schema-mode", String.class).orElse("UPDATE"),
        cfg.getOptionalValue("seal.migration-default", String.class).orElse("LAZY"),
        cfg.getOptionalValue("seal.batch-size", Integer.class).orElse(500),
        cfg.getOptionalValue("seal.drop-legacy", Boolean.class).orElse(false),
        cfg.getOptionalValue("seal.strict-locking", Boolean.class).orElse(true));

    SealedRuntime.RunResult result = doStart(entities, config, dataSource, sealer, indexer);
    String exportPath = cfg.getOptionalValue("seal.export-path", String.class).orElse(null);
    if (exportPath != null && !exportPath.isBlank()) {
      String sql = SealedRuntime.exportFlyway(dataSource, entities, config);
      java.nio.file.Files.writeString(java.nio.file.Path.of(exportPath), sql);
    }
    LOG.info("libseal: ddl aplicado={} migrado={} purgado={}",
        result.appliedDdl().size(), result.migrated(), result.dropped());
  }

  /**
   * Secuencia de arranque sin CDI, testeable de forma determinista.
   * Inicializa el registro estatico y ejecuta reconcile + backfill + purga.
   * El resellador LAZY se registra dentro de {@link SealedRuntime#run}.
   */
  static SealedRuntime.RunResult doStart(List<Class<?>> entities, SealedConfig config,
                                         DataSource ds, Sealer sealer, BlindIndexer indexer) throws Exception {
    return SealedRuntime.run(ds, entities, config, sealer, indexer);
  }
}