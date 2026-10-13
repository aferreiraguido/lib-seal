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

import java.util.List;

/**
 * La app declara las clases {@code @SealedEntity} que debe gestionar libseal.
 * Sin ninguna implementacion (o lista vacia) el bootstrap es no-op.
 * Permite el DTO limpio: no hay classpath-scanning magico.
 */
public interface SealedEntitySource {
  List<Class<?>> sealedEntities();
}