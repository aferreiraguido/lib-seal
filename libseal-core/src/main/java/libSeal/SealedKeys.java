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

import com.google.crypto.tink.Aead;

/**
 * Construye los beans de cripto ({@link Sealer} + {@link BlindIndexer}) desde un
 * {@link KeyProvider}. Unifica el cableado en Quarkus y Spring: la app solo aporta
 * las claves montadas por el cluster (KMS/secret) envueltas en un KeyProvider.
 */
public final class SealedKeys {
  private SealedKeys() {}

  public record Beans(Sealer sealer, BlindIndexer indexer) {}

  public static Beans from(KeyProvider keys) {
    if (keys == null) throw new IllegalArgumentException("keys null");
    Object prim = keys.encryptionPrimitive();
    if (!(prim instanceof Aead)) {
      throw new IllegalArgumentException(
          "KeyProvider.encryptionPrimitive() debe ser un com.google.crypto.tink.Aead, no "
              + (prim == null ? "null" : prim.getClass().getName()));
    }
    Sealer sealer = new TinkSealer((Aead) prim, keys.version());
    BlindIndexer indexer = new HmacBlindIndexer(keys.pepperBytes(), keys.version());
    return new Beans(sealer, indexer);
  }
}