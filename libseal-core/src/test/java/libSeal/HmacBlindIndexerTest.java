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

import java.nio.charset.StandardCharsets;
import org.junit.Test;

public class HmacBlindIndexerTest {

  private static byte[] pepper(String s) {
    byte[] raw = s.getBytes(StandardCharsets.UTF_8);
    byte[] out = new byte[32];
    System.arraycopy(raw, 0, out, 0, Math.min(raw.length, 32));
    return out;
  }

  @Test
  public void hashIsDeterministicAndVersioned() {
    BlindIndexer idx = new HmacBlindIndexer(pepper("pepper-uno-1234567890-abcdef"), "v1");
    String a = idx.hash("hola@x.com", "customer.email");
    String b = idx.hash("hola@x.com", "customer.email");
    assertEquals(a, b);
    assertTrue(a.startsWith("v1:"));
    assertEquals(3 + 64, a.length()); // v1: + hex(sha256)
  }

  @Test
  public void hashNormalizesCaseAndSpaces() {
    BlindIndexer idx = new HmacBlindIndexer(pepper("pepper-uno-1234567890-abcdef"), "v1");
    assertEquals(idx.hash("Hola@X.com ", "d"), idx.hash("hola@x.com", "d"));
  }

  @Test
  public void domainSeparationAndPepperSeparation() {
    BlindIndexer idx = new HmacBlindIndexer(pepper("pepper-uno-1234567890-abcdef"), "v1");
    assertNotEquals(idx.hash("x", "a"), idx.hash("x", "b"));
    BlindIndexer other = new HmacBlindIndexer(pepper("otro-pepper-0987654321-fedcba"), "v1");
    assertNotEquals(idx.hash("x", "a"), other.hash("x", "a"));
  }

  @Test
  public void nullAndEmptyPassthrough() {
    BlindIndexer idx = new HmacBlindIndexer(pepper("pepper-uno-1234567890-abcdef"), "v1");
    assertNull(idx.hash(null, "d"));
    assertEquals("", idx.hash("", "d"));
    assertEquals("", idx.hash("   ", "d"));
  }

  @Test(expected = IllegalArgumentException.class)
  public void shortPepperRejected() {
    new HmacBlindIndexer(new byte[8], "v1");
  }
}
