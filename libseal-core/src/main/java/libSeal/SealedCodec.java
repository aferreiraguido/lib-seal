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
 * Logica pura sin framework: 1 valor logico <-> 3 columnas fisicas.
 * Permite DTO limpio (solo String email) mapeado a legacy/encrypt/hash.
 * Usado por SealedCompositeType (Hibernate) sin duplicar logica en Spring luego.
 */
public final class SealedCodec {
  private final Sealer sealer;
  private final BlindIndexer indexer;

  public SealedCodec(Sealer sealer, BlindIndexer indexer) {
    if (sealer == null || indexer == null) throw new IllegalArgumentException("sealer/indexer null");
    this.sealer = sealer;
    this.indexer = indexer;
  }

  public record EncHash(String encrypt, String hash) {}
  public record Resolved(String legacyCol, String encryptCol, String hashCol) {}

  /** Convencion hibrida: "" = {field}, {field}_se, {field}_sh (_se=sealed-encrypt, _sh=sealed-hash). */
  public static Resolved resolve(String fieldName, Sealed ann) {
    String legacy = ann.legacy().isEmpty() ? fieldName : ann.legacy();
    String encrypt = ann.encrypt().isEmpty() ? fieldName + "_se" : ann.encrypt();
    String hash = ann.hash().isEmpty() ? fieldName + "_sh" : ann.hash();
    if (!ann.searchable()) hash = null;
    return new Resolved(legacy, encrypt, hash);
  }

  /** Java -> columnas. null -> (null,null). */
  public EncHash toColumns(String plain, String domain, boolean searchable) {
    if (plain == null) return new EncHash(null, null);
    String encrypt = sealer.seal(plain, domain);
    String hash = searchable ? indexer.hash(plain, domain) : null;
    return new EncHash(encrypt, hash);
  }

  /**
   * Solo la columna cifrada. Hibernate 6 invoca {@code getPropertyValue} una vez
   * por columna: separar encrypt/hash evita calcular ambos dos veces por escritura.
   * null -> null.
   */
  public String sealEncrypt(String plain, String domain) {
    if (plain == null) return null;
    return sealer.seal(plain, domain);
  }

  /** Solo la columna de busqueda (blind index). null -> null. */
  public String hashOnly(String plain, String domain) {
    if (plain == null) return null;
    return indexer.hash(plain, domain);
  }

  /** Columnas -> Java. Prioridad encrypt descifrado, fallback legacy plano (migracion LAZY). */
  public String fromColumns(String legacy, String encrypt, String domain) {
    if (encrypt != null) {
      if (!SealedSupport.isSealedFormat(encrypt)) return encrypt; // tolerante
      return sealer.unseal(encrypt, domain);
    }
    return legacy; // fila aun no migrada
  }

  public boolean needsMigration(String encrypt) {
    return encrypt == null;
  }
}
