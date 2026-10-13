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

import jakarta.persistence.PostLoad;

/**
 * Fuerza LAZY: si la fila venia de legacy (encrypt==null), hay que reescribirla
 * sellada aunque el valor en Java no cambie. El dirty-check de Hibernate no detecta
 * "mismo valor", asi que {@code @PostLoad} marca la entidad como sucia via
 * {@link SealedRegistry#markDirty(Object)} (marcador ligado al Session actual,
 * registrado por el glue de Quarkus/Spring).
 *
 * <p>Sin marcador registrado (p.ej. Hibernate puro sin sesion accesible) no hace nada:
 * la fila se sellara en el proximo UPDATE real. Con marcador, se sella en el flush.
 * Uso: {@code @EntityListeners(SealedEntityListener.class)}.
 */
public class SealedEntityListener {

  @PostLoad
  public void lazyTouch(Object entity) {
    if (entity == null) return;
    // Solo re-sella si la fila leida venia de legacy (senal del CompositeUserType).
    boolean legacyRow = SealedRegistry.consumeLegacyRow();
    if (!legacyRow) return;
    if (!SealedRegistry.hasDirtyMarker()) return;
    SealedRegistry.markDirty(entity);
  }
}