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
 * Cifrado aleatorio AEAD (AES-GCM via Tink). Framework-agnostico.
 * El aadContext debe ser estable por campo: "tabla.columna" o domain.
 * Implementaciones thread-safe, registrar como singleton.
 */
public interface Sealer {
  String seal(String plain, String aadContext);
  String unseal(String ciphertext, String aadContext);
}
