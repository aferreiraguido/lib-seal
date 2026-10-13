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

/** Entidad top-level para test de binding de seal.entities (FQCN). */
@SealedEntity(domain = "customer", migration = SealedMigration.LAZY)
@jakarta.persistence.Table(name = "customers")
public class ExportedCustomer {
  @jakarta.persistence.Id
  long id;
  @Sealed(domain = "customer.email")
  String email;
}
