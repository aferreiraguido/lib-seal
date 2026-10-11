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

import java.nio.charset.StandardCharsets;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * BlindIndexer HMAC-SHA256 con pepper + domain separation.
 * Formato: "vN:hex(hmac)". Thread-safe salvo Mac (se crea por llamada).
 */
public final class HmacBlindIndexer implements BlindIndexer {
  private final byte[] pepper;
  private final String version;

  public HmacBlindIndexer(byte[] pepper, String version) {
    if (pepper == null || pepper.length < 16) throw new IllegalArgumentException("pepper >=16 bytes");
    this.pepper = pepper.clone();
    this.version = (version == null) ? "v1" : version;
  }

  @Override
  public String normalize(String rawValue) {
    return SealedSupport.normalize(rawValue);
  }

  @Override
  public String hash(String rawValue, String domain) {
    if (rawValue == null) return null;
    String norm = normalize(rawValue);
    if (norm == null || norm.isEmpty()) return norm;
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(pepper, "HmacSHA256"));
      String payload = (domain == null ? "" : domain) + "|" + norm;
      byte[] h = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
      return version + ":" + toHex(h);
    } catch (Exception e) {
      throw new IllegalStateException("hash failed domain=" + domain, e);
    }
  }

  private static String toHex(byte[] b) {
    StringBuilder sb = new StringBuilder(b.length * 2);
    for (byte x : b) sb.append(String.format("%02x", x));
    return sb.toString();
  }
}
