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

/** Config leida de yaml/props montados por el cluster (multi-nube). Prefijo: seal.* */
public final class SealedConfig {
  public enum SchemaMode { VALIDATE, UPDATE, VALIDATE_EXPORT }

  private final SchemaMode schemaMode;
  private final SealedMigration migrationDefault;
  private final int batchSize;
  private final boolean dropLegacy;
  private final boolean strictLocking;

  public SealedConfig(SchemaMode schemaMode, SealedMigration migrationDefault, int batchSize, boolean dropLegacy) {
    this(schemaMode, migrationDefault, batchSize, dropLegacy, true);
  }

  public SealedConfig(SchemaMode schemaMode, SealedMigration migrationDefault, int batchSize, boolean dropLegacy, boolean strictLocking) {
    this.schemaMode = schemaMode;
    this.migrationDefault = migrationDefault;
    this.batchSize = batchSize;
    this.dropLegacy = dropLegacy;
    this.strictLocking = strictLocking;
  }

  public static SealedConfig defaults() {
    return new SealedConfig(SchemaMode.UPDATE, SealedMigration.LAZY, 500, false, true);
  }

  /** Copia sin bloqueo pesimista (motores sin SKIP LOCKED). */
  public SealedConfig withoutLocking() {
    return new SealedConfig(schemaMode, migrationDefault, batchSize, dropLegacy, false);
  }

  public SchemaMode schemaMode() { return schemaMode; }
  public SealedMigration migrationDefault() { return migrationDefault; }
  public int batchSize() { return batchSize; }
  public boolean dropLegacy() { return dropLegacy; }
  public boolean strictLocking() { return strictLocking; }
}
