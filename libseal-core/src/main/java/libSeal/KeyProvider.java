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
 * Provee primitivas ya resueltas desde secretos externos.
 * La app monta los secretos (K8s/SecretManager/otro cloud) como env/props
 * y el provider solo los lee. El core nunca llama a la nube directamente.
 */
public interface KeyProvider {
  /** Primitiva AEAD (Tink) para Sealer. Resuelta al arrancar, cacheada. */
  Object encryptionPrimitive();

  /** Pepper de 32 bytes para BlindIndexer, versionado (v1, v2...). */
  byte[] pepperBytes();

  /** Version activa, ej. "v1". Se prefija en lo guardado. */
  String version();
}
