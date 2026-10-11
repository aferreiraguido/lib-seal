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
 * v2 DTO limpio: el hash lo escribe SealedCompositeType en nullSafeSet.
 * Este listener solo fuerza LAZY: si la fila venia de legacy (encrypt==null),
 * re-asigna el mismo valor para marcar la entidad sucia y que el proximo
 * flush la selle (encrypt+hash) sin codigo manual en el DTO.
 * Uso: {@code @EntityListeners(SealedEntityListener.class)}.
 */
public class SealedEntityListener {

  @PostLoad
  public void lazyTouch(Object entity) {
    if (entity == null) return;
    Class<?> c = entity.getClass();
    if (c.getAnnotation(SealedEntity.class) == null) return;
    // El CompositeType ya devolvio legacy como valor. Re-set para dirty-check:
    for (java.lang.reflect.Field f : c.getDeclaredFields()) {
      if (f.getAnnotation(Sealed.class) == null) continue;
      try {
        f.setAccessible(true);
        Object v = f.get(entity);
        if (v != null) f.set(entity, v);
      } catch (Exception ignored) {}
    }
  }
}
