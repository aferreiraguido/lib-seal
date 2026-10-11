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
 * Marca un campo String como sellado. DTO limpio: solo este campo existe en Java.
 * La lib deriva las columnas fisicas por convencion + override (hibrido):
 * legacy={field} (plano heredado, solo lectura migracion),
 * sealed-encrypt en {field}_se (vN:base64 AEAD), sealed-hash en {field}_sh (vN:hex HMAC).
 * El cifrado real lo hace {@link Sealer} con AAD = domain.
 */
@Documented
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.FIELD)
public @interface Sealed {
  /** Contexto de dominio para AAD y separation, ej. "customer.email". Obligatorio. */
  String domain();

  /** Columna ciphertext. "" = convencion {field}_se. */
  String encrypt() default "";

  /** Columna blind index. "" = convencion {field}_sh. Ignorada si searchable=false. */
  String hash() default "";

  /** Columna legacy plana. "" = convencion {field}. */
  String legacy() default "";

  /** Si false, no crea ni mantiene hash (campo no buscable). */
  boolean searchable() default true;

  /** Longitud de columna recomendada. El ciphertext Base64 expande ~30% + envelope. */
  int columnLength() default 2048;
}
