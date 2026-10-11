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

import org.junit.Test;

public class SealedSupportTest {

  @Test
  public void normalizeTrimsLowersAndNfkc() {
    assertEquals("hola@x.com", SealedSupport.normalize("  Hola@x.com "));
    assertEquals("hola@x.com", SealedSupport.normalize("HOLA@X.COM"));
    assertNull(SealedSupport.normalize(null));
  }

  @Test
  public void isSealedFormatDetectsVersionPrefix() {
    assertTrue(SealedSupport.isSealedFormat("v1:abc"));
    assertTrue(SealedSupport.isSealedFormat("v12:abc"));
    assertFalse(SealedSupport.isSealedFormat("hola@x.com"));
    assertFalse(SealedSupport.isSealedFormat("v:abc"));
    assertFalse(SealedSupport.isSealedFormat(null));
    assertFalse(SealedSupport.isSealedFormat(""));
  }

  @Test
  public void versionOfExtractsOrFallback() {
    assertEquals("v1", SealedSupport.versionOf("v1:abc", "v9"));
    assertEquals("v2", SealedSupport.versionOf("v2:abc", "v9"));
    assertEquals("v9", SealedSupport.versionOf(null, "v9"));
    assertEquals("v9", SealedSupport.versionOf("sin-prefijo", "v9"));
  }
}
