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

import java.util.Base64;

/**
 * KeyProvider que lee secretos ya montados via props/env (multi-nube).
 * No llama a SecretManager/KMS directamente. El cluster monta:
 * SEAL_DEK_B64 no se usa aqui (el DEK/Tink se resuelve fuera), SEAL_PEPPER_B64 si.
 * Para envelope completo, construir el Aead fuera y pasarlo aqui.
 */
public final class ConfigKeyProvider implements KeyProvider {
  private final Object primitive;
  private final byte[] pepper;
  private final String version;

  public ConfigKeyProvider(Object tinkAeadPrimitive, String pepperB64, String version) {
    this.primitive = tinkAeadPrimitive;
    this.pepper = Base64.getDecoder().decode(pepperB64);
    this.version = (version == null) ? "v1" : version;
  }

  @Override public Object encryptionPrimitive() { return primitive; }
  @Override public byte[] pepperBytes() { return pepper.clone(); }
  @Override public String version() { return version; }
}
