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

import io.quarkus.hibernate.orm.panache.PanacheRepository;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Repository Panache con busqueda sellada implicita (DTO limpio). Quarkus 2.13 / javax.
 * Uso:
 * <pre>
 * &#64;ApplicationScoped
 * public class UsuarioRepository implements PanacheSealedRepository&lt;Usuario&gt; {
 *   public Optional&lt;Usuario&gt; findByEmail(String email) {
 *     return findSealed("email", email);
 *   }
 * }
 * </pre>
 * Resuelve Class&lt;T&gt; del generico subiendo del proxy CDI. Cacheado.
 */
public interface PanacheSealedRepository<T> extends PanacheRepository<T> {

  Map<Class<?>, Class<?>> ENTITY_CACHE = new ConcurrentHashMap<>();

  @SuppressWarnings("unchecked")
  default Class<T> sealedEntityClass() {
    Class<?> me = getClass();
    Class<?> cached = ENTITY_CACHE.get(me);
    if (cached != null) return (Class<T>) cached;
    Class<?> c = me;
    while (c != null && c != Object.class) {
      for (Type itf : c.getGenericInterfaces()) {
        Class<T> r = resolve(itf);
        if (r != null) {
          ENTITY_CACHE.put(me, r);
          return r;
        }
      }
      Type sup = c.getGenericSuperclass();
      if (sup instanceof ParameterizedType) {
        Class<T> r = resolve(sup);
        if (r != null) {
          ENTITY_CACHE.put(me, r);
          return r;
        }
      }
      c = c.getSuperclass();
    }
    throw new IllegalStateException("No se pudo inferir Class<T> de " + me
        + ". Usa SealedPanache.findSealed(Usuario.class, field, plain) explicito.");
  }

  @SuppressWarnings("unchecked")
  static <T> Class<T> resolve(Type t) {
    if (!(t instanceof ParameterizedType)) return null;
    ParameterizedType p = (ParameterizedType) t;
    if (!(p.getRawType() instanceof Class)) return null;
    if (!PanacheSealedRepository.class.isAssignableFrom((Class<?>) p.getRawType())) return null;
    Type arg = p.getActualTypeArguments()[0];
    return (arg instanceof Class) ? (Class<T>) arg : null;
  }

  /** Busqueda sellada implicita: hashea y filtra por e.field.hash. null -> empty. */
  default Optional<T> findSealed(String field, String plainValue) {
    SealedPanache bean = javax.enterprise.inject.spi.CDI.current().select(SealedPanache.class).get();
    return bean.find(sealedEntityClass(), field, plainValue);
  }
}
