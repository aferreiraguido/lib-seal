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

import jakarta.persistence.Embeddable;

/**
 * Holder fisico de las 3 columnas de un campo {@code @Sealed}.
 * El ORDEN de atributos es contractual y debe coincidir con el orden
 * de {@code @Columns} en la entidad: [encrypt, hash, legacy].
 * Los nombres definen los sub-paths JPQL: {@code e.email.hash}.
 * NOTA: orden alfabetico (encrypt,hash,legacy) a proposito — Hibernate 6
 * ordena el embeddable alfabeticamente; declararlo ya en ese orden hace
 * que indice==nombre sea estable tanto si usa declaracion como alfabetico.
 * Sin @Column explicito para que mande el @Columns(columns=...) del campo.
 */
@Embeddable
public class SealedColumns {
  public String encrypt;

  public String hash;

  public String legacy;
}
