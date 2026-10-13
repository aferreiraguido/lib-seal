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

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import javax.sql.DataSource;

/**
 * Arranque Spring Boot reutilizable y testeable (no atado a {@code ApplicationRunner}).
 * Reconcilia DDL, backfill STRICT, purga legacy y registra el resellador LAZY via
 * {@link SealedRuntime#run}. Ademas, si {@code seal.export-path} esta definido, escribe
 * el SQL Flyway del DDL pendiente antes de aplicar nada.
 *
 * <p>La auto-configuracion expone un {@code ApplicationRunner} que delega en {@link #run()},
 * de modo que en tests se puede invocar {@code run()} directamente sin levantar la app.
 */
public class SealedSpringBootstrap {
  private final DataSource ds;
  private final SealedConfig config;
  private final Sealer sealer;
  private final BlindIndexer indexer;
  private final SealedSpringProperties props;

  public SealedSpringBootstrap(DataSource ds, SealedConfig config, Sealer sealer,
                               BlindIndexer indexer, SealedSpringProperties props) {
    this.ds = ds;
    this.config = config;
    this.sealer = sealer;
    this.indexer = indexer;
    this.props = props;
  }

  /** Ejecuta la secuencia de arranque. No-op si no hay entidades gestionadas. */
  public SealedRuntime.RunResult run() throws Exception {
    List<Class<?>> entities = props.getEntities();
    if (entities == null || entities.isEmpty()) {
      return new SealedRuntime.RunResult(List.of(), List.of(), List.of());
    }
    if (props.getExportPath() != null && !props.getExportPath().isBlank()) {
      String sql = SealedRuntime.exportFlyway(ds, entities, config);
      Files.writeString(Path.of(props.getExportPath()), sql);
    }
    return SealedRuntime.run(ds, entities, config, sealer, indexer);
  }
}