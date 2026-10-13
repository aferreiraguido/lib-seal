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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.aead.PredefinedAeadParameters;
import java.util.Base64;
import org.junit.BeforeClass;
import org.junit.Test;

/** KeyProvider/ConfigKeyProvider y su cableado a Sealer+BlindIndexer via SealedKeys. */
public class SealedKeysTest {

  private static Aead aead;

  @BeforeClass
  public static void keys() throws Exception {
    AeadConfig.register();
    aead = KeysetHandle.generateNew(PredefinedAeadParameters.AES128_GCM)
        .getPrimitive(RegistryConfiguration.get(), Aead.class);
  }

  @Test
  public void configKeyProviderExposesResolvedPrimitives() {
    byte[] pepper = new byte[32];
    java.util.Arrays.fill(pepper, (byte) 9);
    String pepperB64 = Base64.getEncoder().encodeToString(pepper);
    ConfigKeyProvider kp = new ConfigKeyProvider(aead, pepperB64, "v7");
    assertTrue(kp.encryptionPrimitive() instanceof Aead);
    assertArrayEquals(pepper, kp.pepperBytes());
    assertEquals("v7", kp.version());
    // pepperBytes devuelve copia defensiva
    byte[] b = kp.pepperBytes();
    b[0] = 0;
    assertEquals((byte) 9, kp.pepperBytes()[0]);
  }

  @Test
  public void sealedKeysBuildsWorkingSealerAndIndexer() {
    byte[] pepper = new byte[32];
    java.util.Arrays.fill(pepper, (byte) 4);
    KeyProvider kp = new ConfigKeyProvider(aead, Base64.getEncoder().encodeToString(pepper), "v2");
    SealedKeys.Beans beans = SealedKeys.from(kp);

    String ct = beans.sealer().seal("hola@x.com", "customer.email");
    assertTrue(ct.startsWith("v2:"));
    assertEquals("hola@x.com", beans.sealer().unseal(ct, "customer.email"));

    String h = beans.indexer().hash("Hola@X.com ", "customer.email");
    assertTrue(h.startsWith("v2:"));
    assertEquals(h, beans.indexer().hash("hola@x.com", "customer.email"));
  }

  @Test
  public void sealedKeysRejectsNonTinkPrimitive() {
    KeyProvider bad = new KeyProvider() {
      @Override public Object encryptionPrimitive() { return "no-soy-aead"; }
      @Override public byte[] pepperBytes() { return new byte[32]; }
      @Override public String version() { return "v1"; }
    };
    try {
      SealedKeys.from(bad);
      assertTrue("deberia rechazar primitiva no-Aead", false);
    } catch (IllegalArgumentException expected) {
      assertTrue(expected.getMessage().contains("Aead"));
    }
  }

  /** SealedHash documenta el blind index de un campo; debe ser legible por reflexion. */
  @Test
  public void sealedHashIsDiscoverable() throws Exception {
    class Holder {
      @SealedHash(source = "email", domain = "customer.email")
      String emailHash;
    }
    var f = Holder.class.getDeclaredField("emailHash");
    SealedHash ann = f.getAnnotation(SealedHash.class);
    assertNotNull(ann);
    assertEquals("email", ann.source());
    assertEquals("customer.email", ann.domain());
  }
}