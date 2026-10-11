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
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import com.google.crypto.tink.Aead;
import org.junit.BeforeClass;
import org.junit.Test;

/** Roundtrip real AES-GCM via Tink (aleatorio) + rotacion dual-read. */
public class TinkSealerTest {

  private static Aead aeadV1;
  private static Aead aeadV2;

  @BeforeClass
  public static void keys() throws Exception {
    AeadConfig.register();
    aeadV1 = KeysetHandle.generateNew(PredefinedAeadParameters.AES128_GCM)
        .getPrimitive(RegistryConfiguration.get(), Aead.class);
    aeadV2 = KeysetHandle.generateNew(PredefinedAeadParameters.AES128_GCM)
        .getPrimitive(RegistryConfiguration.get(), Aead.class);
  }

  @Test
  public void roundtripIsRandomButStableOnRead() throws Exception {
    Sealer s = new TinkSealer(aeadV1, "v1");
    String c1 = s.seal("hola@x.com", "customer.email");
    String c2 = s.seal("hola@x.com", "customer.email");
    assertTrue(c1.startsWith("v1:"));
    assertNotEquals(c1, c2); // AEAD aleatorio
    assertEquals("hola@x.com", s.unseal(c1, "customer.email"));
    assertEquals("hola@x.com", s.unseal(c2, "customer.email"));
  }

  @Test
  public void aadMismatchFails() {
    Sealer s = new TinkSealer(aeadV1, "v1");
    String c = s.seal("x", "a");
    try {
      s.unseal(c, "b");
      assertTrue("deberia fallar por AAD", false);
    } catch (IllegalStateException expected) {
      assertTrue(true);
    }
  }

  @Test
  public void nullPassthrough() {
    Sealer s = new TinkSealer(aeadV1, "v1");
    assertNull(s.seal(null, "d"));
    assertNull(s.unseal(null, "d"));
  }

  @Test
  public void rotatingSealerWritesActiveReadsBoth() {
    java.util.Map<String, Sealer> m = new java.util.LinkedHashMap<>();
    m.put("v1", new TinkSealer(aeadV1, "v1"));
    m.put("v2", new TinkSealer(aeadV2, "v2"));
    RotatingSealer r = new RotatingSealer(m, "v1");
    String old = r.seal("a@x.com", "d");
    assertTrue(old.startsWith("v1:"));
    r.rotateTo("v2");
    String current = r.seal("a@x.com", "d");
    assertTrue(current.startsWith("v2:"));
    assertEquals("a@x.com", r.unseal(old, "d")); // dual-read v1
    assertEquals("a@x.com", r.unseal(current, "d"));
    assertEquals("v2", r.active());
  }

  @Test
  public void rotatingIndexerActiveAndDualLookup() {
    byte[] p1 = new byte[32];
    byte[] p2 = new byte[32];
    java.util.Arrays.fill(p1, (byte) 1);
    java.util.Arrays.fill(p2, (byte) 2);
    java.util.Map<String, BlindIndexer> m = new java.util.LinkedHashMap<>();
    m.put("v1", new HmacBlindIndexer(p1, "v1"));
    m.put("v2", new HmacBlindIndexer(p2, "v2"));
    RotatingBlindIndexer r = new RotatingBlindIndexer(m, "v1");
    String h1 = r.hash("a@x.com", "d");
    assertTrue(h1.startsWith("v1:"));
    r.rotateTo("v2");
    assertTrue(r.hash("a@x.com", "d").startsWith("v2:"));
    // lookup dual durante la migracion de pepper
    assertEquals(h1, r.hashWith("v1", "a@x.com", "d"));
  }
}
