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
import java.util.ArrayList;
import java.util.List;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.sql.DataSource;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;

/**
 * Bootstrap Quarkus 2.13 (DB-only, javax). En {@link StartupEvent} ejecuta la
 * secuencia comun {@link SealedRuntime#run}: registra sealer/indexer, reconcilia DDL,
 * backfill STRICT y purga legacy si {@code seal.drop-legacy=true}. Registra ademas el
 * resealer LAZY. La app aporta {@link Sealer}, {@link BlindIndexer} y una o mas
 * implementaciones de {@link SealedEntitySource}.
 */
@ApplicationScoped
public class SealedBootstrap {

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
    if (entities.isEmpty()) return;

    Config cfg = ConfigProvider.getConfig();
    SealedConfig config = SealedConfig.parse(
        cfg.getOptionalValue("seal.schema-mode", String.class).orElse("UPDATE"),
        cfg.getOptionalValue("seal.migration-default", String.class).orElse("LAZY"),
        cfg.getOptionalValue("seal.batch-size", Integer.class).orElse(500),
        cfg.getOptionalValue("seal.drop-legacy", Boolean.class).orElse(false),
        cfg.getOptionalValue("seal.strict-locking", Boolean.class).orElse(true));

    SealedRuntime.run(dataSource, entities, config, sealer, indexer);
  }
}