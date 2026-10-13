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

import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** Propiedades {@code seal.*} montadas por el cluster (multi-nube). */
@ConfigurationProperties(prefix = "seal")
public class SealedSpringProperties {

  /** Pepper HMAC 32B en Base64 (obligatorio para busquedas). */
  private String pepperB64;

  /** Version activa vN para lo que se escribe (lectura multi-version). */
  private String version = "v1";

  private String schemaMode = "UPDATE";
  private String migrationDefault = "LAZY";
  private int batchSize = 500;
  private boolean dropLegacy = false;
  private boolean strictLocking = true;

  /** Si se define, escribe el SQL Flyway del DDL pendiente en esta ruta al arrancar. */
  private String exportPath;

  /** Clases con @SealedEntity a gestionar (nombres FQCN). Vacio = no-op. */
  private List<Class<?>> entities = new ArrayList<>();

  public String getPepperB64() { return pepperB64; }
  public void setPepperB64(String pepperB64) { this.pepperB64 = pepperB64; }
  public String getVersion() { return version; }
  public void setVersion(String version) { this.version = version; }
  public String getSchemaMode() { return schemaMode; }
  public void setSchemaMode(String schemaMode) { this.schemaMode = schemaMode; }
  public String getMigrationDefault() { return migrationDefault; }
  public void setMigrationDefault(String migrationDefault) { this.migrationDefault = migrationDefault; }
  public int getBatchSize() { return batchSize; }
  public void setBatchSize(int batchSize) { this.batchSize = batchSize; }
  public boolean isDropLegacy() { return dropLegacy; }
  public void setDropLegacy(boolean dropLegacy) { this.dropLegacy = dropLegacy; }
  public boolean isStrictLocking() { return strictLocking; }
  public void setStrictLocking(boolean strictLocking) { this.strictLocking = strictLocking; }
  public String getExportPath() { return exportPath; }
  public void setExportPath(String exportPath) { this.exportPath = exportPath; }
  public List<Class<?>> getEntities() { return entities; }
  public void setEntities(List<Class<?>> entities) { this.entities = entities; }
}
