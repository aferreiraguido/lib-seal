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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.Before;
import org.junit.Test;

/** Codec con dobles deterministas: cubre convencion/override, null, fallback legacy. */
public class SealedCodecTest {

  /** Fake reversible con formato vN: para ejercitar la logica sin Tink. */
  static final class FakeSealer implements Sealer {
    @Override public String seal(String plain, String aad) {
      if (plain == null) return null;
      return "v9:" + Base64.getEncoder().encodeToString((aad + "|" + plain).getBytes(StandardCharsets.UTF_8));
    }
    @Override public String unseal(String ct, String aad) {
      String b64 = ct.substring(ct.indexOf(':') + 1);
      String s = new String(Base64.getDecoder().decode(b64), StandardCharsets.UTF_8);
      if (!s.startsWith(aad + "|")) throw new IllegalStateException("AAD mismatch");
      return s.substring(aad.length() + 1);
    }
  }

  static final class FakeIndexer implements BlindIndexer {
    @Override public String normalize(String v) { return SealedSupport.normalize(v); }
    @Override public String hash(String v, String domain) {
      if (v == null) return null;
      return "v9:H(" + domain + "|" + normalize(v) + ")";
    }
  }

  static class Fixture {
    @Sealed(domain = "customer.email")
    String email;
    @Sealed(domain = "customer.email", encrypt = "c_encrypt", hash = "c_hash", legacy = "c_legacy")
    String custom;
    @Sealed(domain = "customer.nif", searchable = false)
    String nif;
  }

  private SealedCodec codec;

  @Before
  public void init() {
    SealedRegistry.init(new FakeSealer(), new FakeIndexer());
    codec = SealedRegistry.codec();
  }

  private static Sealed annOf(String field) throws Exception {
    return Fixture.class.getDeclaredField(field).getAnnotation(Sealed.class);
  }

  @Test
  public void resolveConventionByDefault() throws Exception {
    SealedCodec.Resolved r = SealedCodec.resolve("email", annOf("email"));
    assertEquals("email", r.legacyCol());
    assertEquals("email_se", r.encryptCol());
    assertEquals("email_sh", r.hashCol());
  }

  @Test
  public void resolveHybridOverride() throws Exception {
    SealedCodec.Resolved r = SealedCodec.resolve("custom", annOf("custom"));
    assertEquals("c_legacy", r.legacyCol());
    assertEquals("c_encrypt", r.encryptCol());
    assertEquals("c_hash", r.hashCol());
  }

  @Test
  public void resolveNonSearchableHasNoHash() throws Exception {
    SealedCodec.Resolved r = SealedCodec.resolve("nif", annOf("nif"));
    assertEquals("nif_se", r.encryptCol());
    assertNull(r.hashCol());
  }

  @Test
  public void roundtripAndAadBinding() {
    SealedCodec.EncHash eh = codec.toColumns("hola@x.com", "customer.email", true);
    assertTrue(eh.encrypt().startsWith("v9:"));
    assertEquals("hola@x.com", codec.fromColumns(null, eh.encrypt(), "customer.email"));
    try {
      codec.fromColumns(null, eh.encrypt(), "otro.dominio");
      assertTrue("deberia fallar por AAD", false);
    } catch (IllegalStateException expected) {
      assertTrue(true);
    }
  }

  @Test
  public void nullMapsToNull() {
    SealedCodec.EncHash eh = codec.toColumns(null, "d", true);
    assertNull(eh.encrypt());
    assertNull(eh.hash());
    assertNull(codec.fromColumns(null, null, "d"));
  }

  @Test
  public void legacyFallbackAndTolerantRead() {
    // Fila aun no migrada: encrypt null -> sirve legacy
    assertEquals("plano@x.com", codec.fromColumns("plano@x.com", null, "d"));
    // Valor sin formato (legacy copiado en encrypt por dual-write antiguo) se devuelve tal cual
    assertEquals("plano@x.com", codec.fromColumns(null, "plano@x.com", "d"));
  }

  @Test
  public void nonSearchableOmitsHash() {
    SealedCodec.EncHash eh = codec.toColumns("123", "customer.nif", false);
    assertTrue(eh.encrypt().startsWith("v9:"));
    assertNull(eh.hash());
  }

  @Test
  public void needsMigrationWhenEncryptMissing() {
    assertTrue(codec.needsMigration(null));
    assertFalse(codec.needsMigration("v9:abc"));
  }

  @Test
  public void sealEncryptAndHashOnlyAreIndependent() {
    String enc = codec.sealEncrypt("hola@x.com", "customer.email");
    assertTrue(enc.startsWith("v9:"));
    assertEquals("hola@x.com", codec.fromColumns(null, enc, "customer.email"));
    String h = codec.hashOnly("hola@x.com", "customer.email");
    assertTrue(h.startsWith("v9:"));
    assertNull(codec.sealEncrypt(null, "d"));
    assertNull(codec.hashOnly(null, "d"));
  }

  @Test
  public void emptyAndWhitespaceValuesRoundtrip() {
    // Cadena vacia: se sella (no es null); el fake hashea igualmente
    SealedCodec.EncHash empty = codec.toColumns("", "d", true);
    assertTrue(empty.encrypt().startsWith("v9:"));
    assertEquals("", codec.fromColumns(null, empty.encrypt(), "d"));
    // Con HmacBlindIndexer real, "" y "   " dan hash vacio (short-circuit)
    BlindIndexer real = new HmacBlindIndexer(new byte[16], "v1");
    assertEquals("", real.hash("", "d"));
    assertEquals("", real.hash("   ", "d"));
  }

  @Test
  public void nfkcNormalizationCollapsesCompatibilityForms() {
    // 'é' precompuesto (U+00E9) vs 'e'+combinante (U+0065 U+0301) normalizan igual
    String a = "mail\u00e9@x.com";
    String b = "mail\u0065\u0301@x.com";
    assertEquals(SealedSupport.normalize(a), SealedSupport.normalize(b));
    assertEquals(
        codec.toColumns(a, "d", true).hash(),
        codec.toColumns(b, "d", true).hash());
  }

  @Test
  public void longValueRoundtripsBeyondLegacyColumn() {
    // Valores largos: el ciphertext Base64 expande; el codec no trunca.
    String longValue = "x".repeat(3000) + "@x.com";
    SealedCodec.EncHash eh = codec.toColumns(longValue, "customer.email", true);
    assertTrue(eh.encrypt().length() > longValue.length()); // expansion Base64
    assertEquals(longValue, codec.fromColumns(null, eh.encrypt(), "customer.email"));
  }

  /**
   * Contrato fisico compartido H5&lt;-&gt;H6: mismos nombres de columna por convencion
   * y mismo formato versionado {@code vN:}. Una BD sellada por una rama la lee la otra
   * porque ambas derivan estas columnas del mismo {@link SealedCodec}.
   */
  @Test
  public void physicalContractIsStableAcrossBranches() throws Exception {
    SealedCodec.Resolved r = SealedCodec.resolve("email", annOf("email"));
    assertEquals("email", r.legacyCol());
    assertEquals("email_se", r.encryptCol());
    assertEquals("email_sh", r.hashCol());
    // Formato versionado en ambas columnas
    SealedCodec.EncHash eh = codec.toColumns("a@x.com", "customer.email", true);
    assertTrue(SealedSupport.isSealedFormat(eh.encrypt()));
    assertTrue(SealedSupport.isSealedFormat(eh.hash()));
  }
}
