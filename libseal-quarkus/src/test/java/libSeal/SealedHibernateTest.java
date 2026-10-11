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

import static org.junit.Assert.assertEquals;

import org.junit.Test;

/** El repositorio infiere Class<T> del genérico sin código manual (DTO limpio). */
public class SealedHibernateTest {

  public static class Customer {
    public Long id;
    public String email;
  }

  public static class CustomerRepository implements PanacheSealedRepository<Customer> {
  }

  @Test
  public void repositoryInfersEntityClassImplicitly() {
    CustomerRepository repo = new CustomerRepository();
    assertEquals(Customer.class, repo.sealedEntityClass());
  }
}
