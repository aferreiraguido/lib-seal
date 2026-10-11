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
 * Holder estatico para tipos Hibernate creados por el provider (sin CDI).
 * El bootstrap CDI lo inicializa una vez al arrancar; los tests lo setean a mano.
 * Core puro, sin dependencias de framework para reusar en Spring.
 */
public final class SealedRegistry {
  private static volatile Sealer sealer;
  private static volatile BlindIndexer indexer;

  private SealedRegistry() {}

  public static void init(Sealer s, BlindIndexer i) {
    sealer = s;
    indexer = i;
  }

  public static Sealer sealer() {
    if (sealer == null) throw new IllegalStateException("SealedRegistry.sealer null: llama SealedRegistry.init() en bootstrap");
    return sealer;
  }

  public static BlindIndexer indexer() {
    if (indexer == null) throw new IllegalStateException("SealedRegistry.indexer null: llama SealedRegistry.init() en bootstrap");
    return indexer;
  }

  public static SealedCodec codec() {
    return new SealedCodec(sealer(), indexer());
  }
}
