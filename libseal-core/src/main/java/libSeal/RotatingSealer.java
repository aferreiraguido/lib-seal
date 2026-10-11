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
 * Sealer con rotacion: escribe siempre con la version activa, lee por prefijo {@code vN:}.
 * Sin prefijo (legacy tolerante) usa la version activa. Thread-safe si los delegados lo son.
 */
public final class RotatingSealer implements Sealer {
  private final Map<String, Sealer> byVersion;
  private volatile String active;

  public RotatingSealer(Map<String, Sealer> byVersion, String active) {
    if (byVersion == null || byVersion.isEmpty()) throw new IllegalArgumentException("byVersion vacio");
    if (!byVersion.containsKey(active)) throw new IllegalArgumentException("active sin Sealer: " + active);
    this.byVersion = Collections.unmodifiableMap(new LinkedHashMap<>(byVersion));
    this.active = active;
  }

  /** Rota la escritura a otra version ya registrada. La lectura dual-read no se interrumpe. */
  public void rotateTo(String version) {
    if (!byVersion.containsKey(version)) throw new IllegalArgumentException("version no registrada: " + version);
    this.active = version;
  }

  public String active() { return active; }

  @Override
  public String seal(String plain, String aadContext) {
    if (plain == null) return null;
    return byVersion.get(active).seal(plain, aadContext);
  }

  @Override
  public String unseal(String ciphertext, String aadContext) {
    if (ciphertext == null) return null;
    String v = SealedSupport.versionOf(ciphertext, active);
    Sealer s = byVersion.getOrDefault(v, byVersion.get(active));
    return s.unseal(ciphertext, aadContext);
  }
}
