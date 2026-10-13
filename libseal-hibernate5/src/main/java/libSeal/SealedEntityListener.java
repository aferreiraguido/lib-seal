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

import javax.persistence.PostLoad;

/**
 * Fuerza LAZY: si la fila venia de legacy (encrypt==null), hay que reescribirla
 * sellada aunque el valor en Java no cambie. El dirty-check de Hibernate no detecta
 * "mismo valor", asi que {@code @PostLoad} delega en
 * {@link SealedRegistry#markDirty(Object)} (resellador registrado por el glue de
 * Quarkus 2.13/Spring). Sin marcador registrado no hace nada: la fila se sellara
 * en el proximo UPDATE real.
 * Uso: {@code @EntityListeners(SealedEntityListener.class)}.
 */
public class SealedEntityListener {

  @PostLoad
  public void lazyTouch(Object entity) {
    if (entity == null) return;
    boolean legacyRow = SealedRegistry.consumeLegacyRow();
    if (!legacyRow) return;
    if (!SealedRegistry.hasDirtyMarker()) return;
    SealedRegistry.markDirty(entity);
  }
}
