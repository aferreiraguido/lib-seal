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

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.persistence.EntityManager;
import java.lang.reflect.Field;
import java.util.List;
import java.util.Optional;

/**
 * Finder Panache sin exponer la columna hash al dev.
 * Uso: {@code SealedPanache.findSealed(Customer.class, "email", "hola@x.com")}.
 * Resuelve @Sealed(domain) del field, hashea y busca por sub-propiedad del composite.
 * Intenta {@code e.email.hash}, fallback documentado a metamodelo si tu Hibernate no expone sub-path.
 */
@ApplicationScoped
public class SealedPanache {

  @Inject EntityManager em;
  @Inject BlindIndexer indexer;

  public String hashFor(Class<?> entity, String field, String plainValue) {
    if (plainValue == null) return null;
    try {
      Field f = entity.getDeclaredField(field);
      Sealed ann = f.getAnnotation(Sealed.class);
      if (ann == null) throw new IllegalArgumentException(field + " no es @Sealed en " + entity);
      return indexer.hash(plainValue, ann.domain());
    } catch (NoSuchFieldException e) {
      throw new IllegalArgumentException("field no existe: " + field, e);
    }
  }

  /**
   * Hashes candidatos en todas las versiones (rotación de pepper).
   * Sin rotación devuelve 1 hash; con {@link RotatingBlindIndexer} devuelve uno por
   * versión para que la búsqueda encuentre filas indexadas antes de rotar.
   */
  public List<String> hashesFor(Class<?> entity, String field, String plainValue) {
    if (plainValue == null) return List.of();
    if (indexer instanceof RotatingBlindIndexer r) {
      try {
        Field f = entity.getDeclaredField(field);
        Sealed ann = f.getAnnotation(Sealed.class);
        if (ann == null) throw new IllegalArgumentException(field + " no es @Sealed en " + entity);
        return r.hashesFor(plainValue, ann.domain());
      } catch (NoSuchFieldException e) {
        throw new IllegalArgumentException("field no existe: " + field, e);
      }
    }
    return List.of(hashFor(entity, field, plainValue));
  }

  public <T> Optional<T> find(Class<T> entity, String field, String plainValue) {
    List<String> hashes = hashesFor(entity, field, plainValue);
    if (hashes.isEmpty()) return Optional.empty();
    String ql = hashes.size() == 1
        ? "FROM " + entity.getSimpleName() + " e WHERE e." + field + ".hash = :h"
        : "FROM " + entity.getSimpleName() + " e WHERE e." + field + ".hash IN :hashes";
    var q = em.createQuery(ql, entity).setMaxResults(1);
    if (hashes.size() == 1) q.setParameter("h", hashes.get(0));
    else q.setParameter("hashes", hashes);
    List<T> list = q.getResultList();
    return list.isEmpty() ? Optional.empty() : Optional.of(list.get(0));
  }

  /** Helper estatico para repos Panache sin inyeccion (delega a CDI). */
  public static <T> Optional<T> findSealed(Class<T> entity, String field, String plain) {
    SealedPanache bean = jakarta.enterprise.inject.spi.CDI.current().select(SealedPanache.class).get();
    return bean.find(entity, field, plain);
  }
}
