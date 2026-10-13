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
  private static volatile DirtyMarker dirtyMarker;

  private SealedRegistry() {}

  /**
   * Marca una entidad gestionada como "sucia" para forzar su UPDATE en el proximo
   * flush. Necesario para LAZY: al leer una fila heredada (sin {@code *_se}) hay que
   * reescribirla sellada aunque el valor en Java no cambie; el dirty-check de
   * Hibernate no detecta "mismo valor" y necesita ayuda.
   */
  @FunctionalInterface
  public interface DirtyMarker {
    void mark(Object entity);
  }

  public static void init(Sealer s, BlindIndexer i) {
    sealer = s;
    indexer = i;
  }

  /** Registra (opcional) el marcador de suciedad ligado al Session/EntityManager actual. */
  public static void initDirtyMarker(DirtyMarker marker) {
    dirtyMarker = marker;
  }

  /** Marca la entidad si hay marcador registrado; no falla si no lo hay (best-effort). */
  public static void markDirty(Object entity) {
    DirtyMarker m = dirtyMarker;
    if (m != null) m.mark(entity);
  }

  public static boolean hasDirtyMarker() {
    return dirtyMarker != null;
  }

  /**
   * Aviso de la capa de mapeo (CompositeUserType/nullSafeGet) -> listener: la fila
   * que se acaba de leer venia SIN sellar ({@code *_se IS NULL}, legacy presente).
   * Evita que el listener dispare un re-sellado en cada lectura de filas ya selladas.
   * El flag se consume en el mismo hilo por el listener (PostLoad tras instanciar).
   */
  private static final ThreadLocal<Boolean> LEGACY_ROW = ThreadLocal.withInitial(() -> Boolean.FALSE);

  /** Llamado por el CompositeUserType cuando la fila vino de legacy. */
  public static void signalLegacyRow() {
    LEGACY_ROW.set(Boolean.TRUE);
  }

  /** El listener lo consulta; leerlo limpia el flag (una lectura = una senal). */
  public static boolean consumeLegacyRow() {
    boolean v = Boolean.TRUE.equals(LEGACY_ROW.get());
    LEGACY_ROW.remove();
    return v;
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
