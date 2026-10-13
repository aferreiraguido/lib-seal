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

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** SealedPanache emite `= :h` sin rotación e `IN :hashes` con rotación de pepper. */
public class SealedPanacheTest {

  static class User {
    @Sealed(domain = "customer.email")
    String email;
  }

  static final class FixedIndexer implements BlindIndexer {
    private final String prefix;
    FixedIndexer(String prefix) { this.prefix = prefix; }
    @Override public String normalize(String v) { return SealedSupport.normalize(v); }
    @Override public String hash(String v, String domain) {
      if (v == null) return null;
      return prefix + ":H(" + domain + "|" + normalize(v) + ")";
    }
  }

  @SuppressWarnings({"unchecked", "rawtypes"})
  private static TypedQuery<User> queryReturning(EntityManager em, User user) {
    TypedQuery q = mock(TypedQuery.class);
    when(em.createQuery(anyString(), eq(User.class))).thenReturn(q);
    when(q.setMaxResults(1)).thenReturn(q);
    when(q.setParameter(anyString(), any())).thenReturn(q);
    when(q.setParameter(anyString(), anyList())).thenReturn(q);
    when(q.getResultList()).thenReturn(user == null ? List.of() : List.of(user));
    return q;
  }

  @Test
  public void singleHashUsesEqualsQuery() {
    EntityManager em = mock(EntityManager.class);
    User user = new User();
    TypedQuery<User> q = queryReturning(em, user);
    SealedPanache panache = new SealedPanache();
    inject(panache, "em", em);
    inject(panache, "indexer", new FixedIndexer("v1"));

    Optional<User> found = panache.find(User.class, "email", "Hola@X.com ");

    assertTrue(found.isPresent());
    ArgumentCaptor<String> ql = ArgumentCaptor.forClass(String.class);
    verify(em).createQuery(ql.capture(), eq(User.class));
    assertTrue(ql.getValue().contains("e.email.hash = :h"));
    verify(q).setParameter(eq("h"), eq("v1:H(customer.email|hola@x.com)"));
    verify(q, never()).setParameter(eq("hashes"), anyList());
  }

  @Test
  public void rotatingIndexerUsesInQueryAcrossVersions() {
    EntityManager em = mock(EntityManager.class);
    User user = new User();
    TypedQuery<User> q = queryReturning(em, user);
    Map<String, BlindIndexer> byVersion = new LinkedHashMap<>();
    byVersion.put("v1", new FixedIndexer("v1"));
    byVersion.put("v2", new FixedIndexer("v2"));
    SealedPanache panache = new SealedPanache();
    inject(panache, "em", em);
    inject(panache, "indexer", new RotatingBlindIndexer(byVersion, "v2"));

    panache.find(User.class, "email", "a@x.com");

    ArgumentCaptor<String> ql = ArgumentCaptor.forClass(String.class);
    verify(em).createQuery(ql.capture(), eq(User.class));
    assertTrue(ql.getValue().contains("IN :hashes"));
    ArgumentCaptor<List> hashes = ArgumentCaptor.forClass(List.class);
    verify(q).setParameter(eq("hashes"), hashes.capture());
    assertEquals(List.of("v1:H(customer.email|a@x.com)", "v2:H(customer.email|a@x.com)"),
        hashes.getValue());
  }

  @Test
  public void nullReturnsEmptyWithoutQuery() {
    EntityManager em = mock(EntityManager.class);
    SealedPanache panache = new SealedPanache();
    inject(panache, "em", em);
    inject(panache, "indexer", new FixedIndexer("v1"));
    assertTrue(panache.find(User.class, "email", null).isEmpty());
    verify(em, never()).createQuery(anyString(), eq(User.class));
  }

  private static void inject(Object target, String field, Object value) {
    try {
      var f = target.getClass().getDeclaredField(field);
      f.setAccessible(true);
      f.set(target, value);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }
}