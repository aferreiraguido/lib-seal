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
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/** El repositorio infiere Class<T> del genérico sin código manual (DTO limpio). */
public class SealedHibernateTest {

  public static class Customer {
    public Long id;
    public String email;
  }

  public static class CustomerRepository implements PanacheSealedRepository<Customer> {
  }

  /** Repo que hereda de otro repo: el genérico está en la superclase. */
  public static abstract class BaseRepo<T> implements PanacheSealedRepository<T> {
  }

  public static class CustomerRepoViaSuper extends BaseRepo<Customer> {
  }

  /** Sin genérico concreto: no se puede inferir Class<T>. */
  public static class RawRepository implements PanacheSealedRepository {
  }

  @Test
  public void repositoryInfersEntityClassImplicitly() {
    CustomerRepository repo = new CustomerRepository();
    assertEquals(Customer.class, repo.sealedEntityClass());
  }

  @Test
  public void repositoryInfersEntityClassViaSuperclassGeneric() {
    assertEquals(Customer.class, new CustomerRepoViaSuper().sealedEntityClass());
  }

  @Test
  public void repositoryCacheReturnsConsistentResult() {
    CustomerRepository repo = new CustomerRepository();
    assertEquals(Customer.class, repo.sealedEntityClass());
    assertEquals(Customer.class, repo.sealedEntityClass()); // segunda vez: cache
  }

  @Test
  public void rawRepositoryFailsWithActionableMessage() {
    try {
      new RawRepository().sealedEntityClass();
      assertTrue("deberia lanzar por no poder inferir Class<T>", false);
    } catch (IllegalStateException expected) {
      assertTrue(expected.getMessage().contains("SealedPanache.findSealed"));
    }
  }
}
