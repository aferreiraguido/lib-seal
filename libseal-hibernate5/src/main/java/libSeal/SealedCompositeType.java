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

import java.io.Serializable;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.Objects;
import java.util.Properties;
import org.hibernate.HibernateException;
import org.hibernate.engine.spi.SharedSessionContractImplementor;
import org.hibernate.type.StringType;
import org.hibernate.type.Type;
import org.hibernate.usertype.CompositeUserType;
import org.hibernate.usertype.DynamicParameterizedType;

/**
 * 1 campo Java String {@code @Sealed} &lt;-&gt; 3 columnas fisicas [legacy, encrypt, hash]
 * via API Hibernate 5.6 (javax, Quarkus 2.13). DTO limpio: la entidad solo declara
 * {@code String email}.
 *
 * <p>El dominio se pasa por subclase (una por campo sellado), igual que en Hibernate 6:
 * <pre>
 * public static class EmailType extends SealedCompositeType {
 *   public EmailType() { super("customer.email", true); }
 * }
 * &#64;Type(type = "com.tuapp.EmailType")
 * &#64;Columns(columns = {
 *   &#64;Column(name = "email"),
 *   &#64;Column(name = "email_se", length = 2048),
 *   &#64;Column(name = "email_sh", length = 128)
 * })
 * &#64;Sealed(domain = "customer.email")
 * public String email;
 * </pre>
 * El orden de {@code @Columns} debe coincidir con {@link #getPropertyNames()}
 * ({@code [legacy, encrypt, hash]}). {@code @Sealed} sigue siendo la fuente de verdad
 * para DDL/migración/búsqueda ({@code SealedModels}, {@code SealedMigrator}).
 * Escritura dual-write: legacy guarda copia en claro (rollback seguro, purga explícita
 * con drop-legacy), encrypt+hash lo sellado.
 */
public class SealedCompositeType implements CompositeUserType, DynamicParameterizedType {

  private String domain = "default";
  private boolean searchable = true;

  public SealedCompositeType() {}

  public SealedCompositeType(String domain, boolean searchable) {
    if (domain != null && !domain.isEmpty()) this.domain = domain;
    this.searchable = searchable;
  }

  @Override
  @SuppressWarnings("rawtypes")
  public void setParameterValues(Properties params) {
    // Compat: si se declaran @Parameter explícitos se respetan; el dominio
    // habitual viene del constructor de la subclase por campo.
    Object entity = params.get(ENTITY);
    Object prop = params.get(PROPERTY);
    String fieldName = (prop instanceof String) ? (String) prop : "";
    try {
      Class<?> ec = null;
      if (entity instanceof Class) ec = (Class<?>) entity;
      else if (entity != null) ec = entity.getClass();
      if (ec != null && !fieldName.isEmpty()) {
        java.lang.reflect.Field f = ec.getDeclaredField(fieldName);
        Sealed ann = f.getAnnotation(Sealed.class);
        if (ann != null) {
          domain = ann.domain();
          searchable = ann.searchable();
        }
      }
    } catch (Exception ignored) {}
    Object d = params.get("domain");
    if (d instanceof String && !((String) d).isEmpty()) domain = (String) d;
    Object s = params.get("searchable");
    if (s instanceof String) searchable = Boolean.parseBoolean((String) s);
    else if (s instanceof Boolean) searchable = (Boolean) s;
  }

  /** Orden contractual: debe coincidir con el orden de {@code @Columns} en la entidad. */
  @Override
  public String[] getPropertyNames() {
    return new String[] {"legacy", "encrypt", "hash"};
  }

  @Override
  public Type[] getPropertyTypes() {
    return new Type[] {StringType.INSTANCE, StringType.INSTANCE, StringType.INSTANCE};
  }

  @Override
  public Object getPropertyValue(Object component, int property) throws HibernateException {
    String plain = (String) component;
    if (plain == null) return null;
    try {
      SealedCodec codec = SealedRegistry.codec();
      switch (property) {
        case 0: return plain; // legacy dual-write en claro
        case 1: return codec.sealEncrypt(plain, domain);
        case 2: return searchable ? codec.hashOnly(plain, domain) : null;
        default: throw new HibernateException("SealedCompositeType: propiedad " + property + " fuera de [0,2]");
      }
    } catch (HibernateException e) {
      throw e;
    } catch (Exception e) {
      throw new HibernateException("seal failed domain=" + domain, e);
    }
  }

  @Override
  public void setPropertyValue(Object component, int property, Object value) throws HibernateException {
    // Inmutable (String): no hay estado que actualizar. Hibernate usa deepCopy/replace.
  }

  @Override
  public Class returnedClass() {
    return String.class;
  }

  @Override
  public boolean equals(Object x, Object y) throws HibernateException {
    return Objects.equals(x, y);
  }

  @Override
  public int hashCode(Object x) throws HibernateException {
    return Objects.hashCode(x);
  }

  @Override
  public Object nullSafeGet(ResultSet rs, String[] names, SharedSessionContractImplementor session, Object owner)
      throws HibernateException, SQLException {
    String legacy = rs.getString(names[0]);
    String encrypt = rs.getString(names[1]);
    if (legacy == null && encrypt == null) return null;
    if (encrypt == null && legacy != null) {
      SealedRegistry.signalLegacyRow(); // fila heredada: el listener la sellara
    }
    try {
      return SealedRegistry.codec().fromColumns(legacy, encrypt, domain);
    } catch (Exception e) {
      throw new HibernateException("unseal failed domain=" + domain, e);
    }
  }

  @Override
  public void nullSafeSet(PreparedStatement st, Object value, int index, SharedSessionContractImplementor session)
      throws HibernateException, SQLException {
    if (value == null) {
      st.setNull(index, Types.VARCHAR);
      st.setNull(index + 1, Types.VARCHAR);
      st.setNull(index + 2, Types.VARCHAR);
      return;
    }
    try {
      String plain = (String) value;
      SealedCodec codec = SealedRegistry.codec();
      SealedCodec.EncHash eh = codec.toColumns(plain, domain, searchable);
      st.setString(index, plain); // legacy dual-write
      st.setString(index + 1, eh.encrypt());
      if (searchable) st.setString(index + 2, eh.hash());
      else st.setNull(index + 2, Types.VARCHAR);
    } catch (HibernateException e) {
      throw e;
    } catch (Exception e) {
      throw new HibernateException("seal failed domain=" + domain, e);
    }
  }

  @Override
  public Object deepCopy(Object value) throws HibernateException {
    return value; // String inmutable
  }

  @Override
  public boolean isMutable() {
    return false;
  }

  @Override
  public Serializable disassemble(Object value, SharedSessionContractImplementor session) throws HibernateException {
    return (Serializable) value;
  }

  @Override
  public Object assemble(Serializable cached, SharedSessionContractImplementor session, Object owner)
      throws HibernateException {
    return cached;
  }

  @Override
  public Object replace(Object original, Object target, SharedSessionContractImplementor session, Object owner)
      throws HibernateException {
    return original;
  }

  /** Visible para tests: dominio del constructor de la subclase. */
  String getDomain() {
    return domain;
  }
}
