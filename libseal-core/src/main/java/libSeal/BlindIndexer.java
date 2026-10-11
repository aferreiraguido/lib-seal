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
 * Blind index HMAC-SHA256 para busquedas exactas DB-agnosticas.
 * El pepper viene de secreto externo (montado via yaml/env, nunca en repo).
 */
public interface BlindIndexer {
  /** Devuelve "vN:hex" listo para guardar en columna *_sh. Null in -&gt; null out. */
  String hash(String rawValue, String domain);

  /** Normalizacion canonica antes de hashear: trim + lowercase ROOT + NFKC. */
  String normalize(String rawValue);
}
