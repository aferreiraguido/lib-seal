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
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

/**
 * @deprecated v2 usa {@link SealedCompositeType} (1 campo -&gt; 3 columnas) para DTO limpio.
 * Se mantiene una version para compat con v1 de 3 campos. No usar en entidades nuevas.
 */
@Deprecated
@Converter
@ApplicationScoped
public class SealedStringConverter implements AttributeConverter<String, String> {

  @Inject Sealer sealer;

  /** Dominio AAD por defecto si la entidad no lo resuelve. Sobrescribir por campo en v2. */
  public String domain() { return "default"; }

  @Override
  public String convertToDatabaseColumn(String attribute) {
    if (attribute == null) return null;
    return sealer.seal(attribute, domain());
  }

  @Override
  public String convertToEntityAttribute(String dbData) {
    if (dbData == null) return null;
    // Compat legacy plano: si no tiene formato vN:, se devuelve tal cual para migrar en listener.
    if (!SealedSupport.isSealedFormat(dbData)) return dbData;
    return sealer.unseal(dbData, domain());
  }
}
