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

/**
 * Politica de migracion plano -> sellado por entidad.
 *
 * <ul>
 *   <li>DISABLED: no migra, solo cifra lo nuevo.</li>
 *   <li>LAZY: migra al leer/insertar/actualizar cada fila (sin downtime).</li>
 *   <li>STRICT: backfill bloqueante al arrancar, por lotes con SKIP LOCKED.</li>
 *   <li>STRICT_LAZY: strict al arrancar + lazy para lo concurrente.</li>
 * </ul>
 */
public enum SealedMigration {
  DISABLED,
  LAZY,
  STRICT,
  STRICT_LAZY
}
