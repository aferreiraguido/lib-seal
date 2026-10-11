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

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Blind index buscable para un campo {@link Sealed}. Columna extra DB-agnostica.
 *
 * <p>Guarda {@code vN:hex(HMAC_SHA256(pepper, domain + "|" + normalize(source)))}.
 * La busqueda es siempre por igualdad exacta sobre esta columna, nunca sobre
 * la columna cifrada. Nunca uses LIKE/rangos sobre un campo sellado.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface SealedHash {
  /** Nombre del campo Java fuente sellado, ej. "email". */
  String source();

  /** Mismo dominio que el @Sealed fuente, ej. "customer.email". */
  String domain();
}
