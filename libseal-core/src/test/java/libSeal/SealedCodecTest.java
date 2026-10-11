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
}
