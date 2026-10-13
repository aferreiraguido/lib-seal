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

import java.lang.reflect.Field;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.util.ArrayList;
import java.util.List;
import javax.sql.DataSource;

/**
 * Re-sella una entidad concreta ya cargada (mecanismo LAZY de escritura diferida).
 *
 * <p>El dirty-check de Hibernate no detecta "mismo valor en Java, pero fila sin
 * sellar en DB", y un lock request no reescribe. Por eso LAZY no puede apoyarse en
 * el flush: cuando el listener detecta una fila heredada, esta clase emite un
 * {@code UPDATE ... SET *_se, *_sh WHERE id} explicito y portable, campo a campo.
 *
 * <p>Es idempotente (solo actua sobre filas con {@code *_se IS NULL}) y no requiere
 * una Session: solo un {@link DataSource}. Se registra en {@link SealedRegistry} como
 * {@link SealedRegistry.DirtyMarker} desde el glue (Quarkus/Spring) o en tests.
 */
public final class SealedResealer {
  private final DataSource ds;
  private final SealedConfig config;
  private final Sealer sealer;
  private final BlindIndexer indexer;
  private final List<SealedModels.EntityModel> models;

  public SealedResealer(DataSource ds, SealedConfig config, Sealer sealer, BlindIndexer indexer,
                        List<SealedModels.EntityModel> models) {
    this.ds = ds;
    this.config = config;
    this.sealer = sealer;
    this.indexer = indexer;
    this.models = models;
  }

  /** Marcador listo para {@link SealedRegistry#initDirtyMarker}: sella la entidad dada. */
  public SealedRegistry.DirtyMarker marker() {
    return this::reseal;
  }

  /** Sella (si hace falta) una entidad concreta. No-op si su clase no esta gestionada. */
  public void reseal(Object entity) {
    if (entity == null) return;
    SealedModels.EntityModel m = modelFor(entity.getClass());
    if (m == null || m.fields().isEmpty()) return;
    Object id = idValue(entity, m);
    if (id == null) return;
    SealedCodec codec = new SealedCodec(sealer, indexer);
    for (SealedModels.FieldModel f : m.fields()) {
      SealedCodec.Resolved cols = f.cols();
      boolean searchable = cols.hashCol() != null;
      String plain = plainValue(entity, f);
      if (plain == null) continue;
      SealedCodec.EncHash eh = codec.toColumns(plain, f.ann().domain(), searchable);
      String sql = "UPDATE " + m.table() + " SET " + cols.encryptCol() + " = ?"
          + (searchable ? ", " + cols.hashCol() + " = ?" : "")
          + " WHERE " + m.idColumn() + " = ? AND " + cols.encryptCol() + " IS NULL";
      try (Connection cn = ds.getConnection(); PreparedStatement ps = cn.prepareStatement(sql)) {
        int i = 1;
        ps.setString(i++, eh.encrypt());
        if (searchable) ps.setString(i++, eh.hash());
        ps.setObject(i, id);
        ps.executeUpdate();
      } catch (Exception e) {
        throw new IllegalStateException("reseal failed table=" + m.table() + " id=" + id, e);
      }
    }
  }

  private SealedModels.EntityModel modelFor(Class<?> c) {
    Class<?> real = unwrapProxy(c);
    for (SealedModels.EntityModel m : models) {
      if (m.entity().equals(real)) return m;
    }
    return null;
  }

  private static Class<?> unwrapProxy(Class<?> c) {
    // Hibernate proxies extienden la entidad: sube hasta la superclase anotada.
    Class<?> cur = c;
    while (cur != null && cur.getAnnotation(SealedEntity.class) == null) {
      cur = cur.getSuperclass();
    }
    return cur != null ? cur : c;
  }

  private static Object idValue(Object entity, SealedModels.EntityModel m) {
    Class<?> c = unwrapProxy(entity.getClass());
    for (Field f : allFields(c)) {
      if (m.idField().equals(f.getName())) {
        try { f.setAccessible(true); return f.get(entity); } catch (Exception ignored) { return null; }
      }
    }
    return null;
  }

  private static String plainValue(Object entity, SealedModels.FieldModel f) {
    Class<?> c = unwrapProxy(entity.getClass());
    for (Field fl : allFields(c)) {
      if (fl.getName().equals(f.field())) {
        try { fl.setAccessible(true); Object v = fl.get(entity); return v == null ? null : v.toString(); }
        catch (Exception ignored) { return null; }
      }
    }
    return null;
  }

  private static List<Field> allFields(Class<?> c) {
    List<Field> out = new ArrayList<>();
    for (Class<?> cur = c; cur != null && cur != Object.class; cur = cur.getSuperclass()) {
      for (Field f : cur.getDeclaredFields()) out.add(f);
    }
    return out;
  }
}