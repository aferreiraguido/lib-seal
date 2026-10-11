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
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Sealer basado en Tink Aead AES-GCM aleatorio.
 * Formato guardado: "vN:base64(nonce|ciphertext|tag + DEK envelope si aplica)".
 * AAD = dominio del campo, evita trasplantar ciphertext entre columnas/filas.
 */
public final class TinkSealer implements Sealer {
  private final Aead aead;
  private final String version;

  public TinkSealer(Aead aead, String version) {
    if (aead == null) throw new IllegalArgumentException("aead null");
    this.aead = aead;
    this.version = (version == null) ? "v1" : version;
  }

  @Override
  public String seal(String plain, String aadContext) {
    if (plain == null) return null;
    try {
      byte[] aad = aadBytes(aadContext);
      byte[] ct = aead.encrypt(plain.getBytes(StandardCharsets.UTF_8), aad);
      return version + ":" + Base64.getEncoder().encodeToString(ct);
    } catch (Exception e) {
      throw new IllegalStateException("seal failed domain=" + aadContext, e);
    }
  }

  @Override
  public String unseal(String ciphertext, String aadContext) {
    if (ciphertext == null) return null;
    try {
      int i = ciphertext.indexOf(':');
      String b64 = (i >= 0) ? ciphertext.substring(i + 1) : ciphertext;
      byte[] ct = Base64.getDecoder().decode(b64);
      byte[] pt = aead.decrypt(ct, aadBytes(aadContext));
      return new String(pt, StandardCharsets.UTF_8);
    } catch (Exception e) {
      throw new IllegalStateException("unseal failed domain=" + aadContext, e);
    }
  }

  private static byte[] aadBytes(String ctx) {
    return (ctx == null ? "" : ctx).getBytes(StandardCharsets.UTF_8);
  }
}
