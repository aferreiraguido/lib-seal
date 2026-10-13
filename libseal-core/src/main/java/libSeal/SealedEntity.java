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
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marca una entidad JPA como gestionada por libseal (DB-only).
 * El bootstrap verifica por modelo/tabla al arrancar y ajusta DDL + migra.
 * {@code @Inherited} para que las subclases (y proxies de Hibernate) la hereden.
 */
@Documented
@Inherited
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
public @interface SealedEntity {
  /** Dominio raiz para AAD, ej. "customer". */
  String domain() default "";

  /** Politica de migracion. Sobrescribible por yaml: seal.migration-default. */
  SealedMigration migration() default SealedMigration.LAZY;
}
