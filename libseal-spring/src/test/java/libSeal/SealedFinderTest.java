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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/** SealedFinder emite `= :h` sin rotación e `IN :hashes` con RotatingBlindIndexer. */
class SealedFinderTest {

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
  void singleHashUsesEqualsQuery() {
    EntityManager em = mock(EntityManager.class);
    User user = new User();
    TypedQuery<User> q = queryReturning(em, user);
    SealedFinder finder = new SealedFinder(em, new FixedIndexer("v1"));

    Optional<User> found = finder.find(User.class, "email", "Hola@X.com ");

    assertThat(found).contains(user);
    ArgumentCaptor<String> ql = ArgumentCaptor.forClass(String.class);
    verify(em).createQuery(ql.capture(), eq(User.class));
    assertThat(ql.getValue()).contains("e.email.hash = :h");
    verify(q).setParameter(eq("h"), eq("v1:H(customer.email|hola@x.com)"));
    verify(q, never()).setParameter(eq("hashes"), anyList());
  }

  @Test
  void rotatingIndexerUsesInQuery() {
    EntityManager em = mock(EntityManager.class);
    User user = new User();
    TypedQuery<User> q = queryReturning(em, user);
    Map<String, BlindIndexer> byVersion = new LinkedHashMap<>();
    byVersion.put("v1", new FixedIndexer("v1"));
    byVersion.put("v2", new FixedIndexer("v2"));
    SealedFinder finder = new SealedFinder(em, new RotatingBlindIndexer(byVersion, "v2"));

    Optional<User> found = finder.find(User.class, "email", "a@x.com");

    assertThat(found).contains(user);
    ArgumentCaptor<String> ql = ArgumentCaptor.forClass(String.class);
    verify(em).createQuery(ql.capture(), eq(User.class));
    assertThat(ql.getValue()).contains("IN :hashes");
    ArgumentCaptor<List> hashes = ArgumentCaptor.forClass(List.class);
    verify(q).setParameter(eq("hashes"), hashes.capture());
    assertThat(hashes.getValue()).containsExactly(
        "v1:H(customer.email|a@x.com)", "v2:H(customer.email|a@x.com)");
  }

  @Test
  void nullReturnsEmptyWithoutQuery() {
    EntityManager em = mock(EntityManager.class);
    SealedFinder finder = new SealedFinder(em, new FixedIndexer("v1"));
    assertThat(finder.find(User.class, "email", null)).isEmpty();
    verify(em, never()).createQuery(anyString(), eq(User.class));
  }
}
