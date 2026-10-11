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

import java.text.Normalizer;
import java.util.Locale;

/** Utilidades compartidas: normalizacion, formato versionado, nulos. */
public final class SealedSupport {
  private SealedSupport() {}

  public static String normalize(String raw) {
    if (raw == null) return null;
    String t = raw.trim().toLowerCase(Locale.ROOT);
    return Normalizer.normalize(t, Normalizer.Form.NFKC);
  }

  public static boolean isSealedFormat(String v) {
    return v != null && v.matches("^v\\d+:.+");
  }

  public static String versionOf(String v, String fallback) {
    if (v == null) return fallback;
    int i = v.indexOf(':');
    return (i > 0) ? v.substring(0, i) : fallback;
  }
}
