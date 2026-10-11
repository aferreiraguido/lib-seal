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

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * BlindIndexer con rotacion de pepper: hashea con la version activa.
 * Durante la migracion de pepper conviven v1+v2; el lookup debe probar ambas
 * (OR sobre las dos columnas hash o doble query) hasta re-indexar.
 */
public final class RotatingBlindIndexer implements BlindIndexer {
  private final Map<String, BlindIndexer> byVersion;
  private volatile String active;

  public RotatingBlindIndexer(Map<String, BlindIndexer> byVersion, String active) {
    if (byVersion == null || byVersion.isEmpty()) throw new IllegalArgumentException("byVersion vacio");
    if (!byVersion.containsKey(active)) throw new IllegalArgumentException("active sin indexer: " + active);
    this.byVersion = Collections.unmodifiableMap(new LinkedHashMap<>(byVersion));
    this.active = active;
  }

  public void rotateTo(String version) {
    if (!byVersion.containsKey(version)) throw new IllegalArgumentException("version no registrada: " + version);
    this.active = version;
  }

  public String active() { return active; }

  /** Versiones registradas (para lookup dual durante la migracion de pepper). */
  public java.util.Set<String> versions() { return byVersion.keySet(); }

  /** Hashes candidatos en todas las versiones (viejas primero para IN queries). */
  public java.util.List<String> hashesFor(String rawValue, String domain) {
    if (rawValue == null) return java.util.Collections.emptyList();
    java.util.List<String> out = new java.util.ArrayList<>();
    for (BlindIndexer b : byVersion.values()) {
      String h = b.hash(rawValue, domain);
      if (h != null && !out.contains(h)) out.add(h);
    }
    return out;
  }

  /** Hash con una version concreta (para lookup dual durante la migracion). */
  public String hashWith(String version, String rawValue, String domain) {
    BlindIndexer b = byVersion.get(version);
    if (b == null) throw new IllegalArgumentException("version no registrada: " + version);
    return b.hash(rawValue, domain);
  }

  @Override
  public String normalize(String rawValue) {
    return byVersion.get(active).normalize(rawValue);
  }

  @Override
  public String hash(String rawValue, String domain) {
    if (rawValue == null) return null;
    return byVersion.get(active).hash(rawValue, domain);
  }
}
