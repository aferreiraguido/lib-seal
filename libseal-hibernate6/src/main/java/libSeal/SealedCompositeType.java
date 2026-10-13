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
import java.util.Objects;
import java.util.Properties;
import org.hibernate.HibernateException;
import org.hibernate.engine.spi.SessionFactoryImplementor;
import org.hibernate.metamodel.spi.ValueAccess;
import org.hibernate.usertype.CompositeUserType;
import org.hibernate.usertype.DynamicParameterizedType;

/**
 * 1 campo Java String {@code @Sealed} &lt;-&gt; 3 columnas fisicas [encrypt, hash, legacy]
 * via {@link SealedColumns}. DTO limpio: la entidad solo declara {@code String email}.
 *
 * <p>Hibernate 6: {@code @CompositeType} no acepta parametros, asi que
 * {@code DynamicParameterizedType.setParameterValues} nunca se llama.
 * El dominio se pasa por subclase (patron recomendado por Hibernate):
 * <pre>
 * public static class EmailType extends SealedCompositeType {
 *   public EmailType() { super("customer.email", true); }
 * }
 * &#64;CompositeType(EmailType.class)
 * &#64;AttributeOverrides({
 *   &#64;AttributeOverride(name="encrypt", column=&#64;Column(name="email_se", length=2048)),
 *   &#64;AttributeOverride(name="hash", column=&#64;Column(name="email_sh", length=128)),
 *   &#64;AttributeOverride(name="legacy", column=&#64;Column(name="email"))
 * })
 * &#64;Sealed(domain="customer.email")
 * public String email;
 * </pre>
 * {@code @Sealed} sigue siendo la fuente de verdad para DDL/migracion/busqueda
 * ({@code SealedModels}, {@code SealedMigrator}, {@code SealedPanache}).
 * Escritura dual-write: legacy guarda copia en claro (rollback seguro, purga explicita
 * con drop-legacy), encrypt+hash lo sellado.
 */
public class SealedCompositeType implements CompositeUserType<String>, DynamicParameterizedType {

  private String domain = "default";
  private boolean searchable = true;

  public SealedCompositeType() {}

  public SealedCompositeType(String domain, boolean searchable) {
    if (domain != null && !domain.isEmpty()) this.domain = domain;
    this.searchable = searchable;
  }

  @Override
  public void setParameterValues(Properties params) {
    // Hibernate 6 no lo llama para @CompositeType; se mantiene por compat.
    // El dominio real viene del constructor de la subclase por campo.
    Object d = params.get("domain");
    if (d instanceof String && !((String) d).isEmpty()) domain = (String) d;
    Object s = params.get("searchable");
    if (s instanceof String) searchable = Boolean.parseBoolean((String) s);
    else if (s instanceof Boolean) searchable = (Boolean) s;
  }

  @Override public Class<?> embeddable() { return SealedColumns.class; }
  @Override public Class<String> returnedClass() { return String.class; }
  @Override public boolean isMutable() { return false; }
  @Override public boolean equals(String x, String y) { return Objects.equals(x, y); }
  @Override public int hashCode(String x) { return Objects.hashCode(x); }
  @Override public String deepCopy(String v) { return v; }
  @Override public Serializable disassemble(String v) { return v; }
  @Override public String assemble(Serializable c, Object o) { return (String) c; }
  @Override public String replace(String o, String t, Object owner) { return o; }

  /** Visible para tests: dominio del constructor de la subclase. */
  String getDomain() { return domain; }

  /**
   * Memo por hilo del ultimo valor sellado: Hibernate 6 invoca {@code getPropertyValue}
   * varias veces por columna y por fila durante un mismo flush, y el tipo es un
   * singleton por SessionFactory. Cachear el ultimo par (encrypt,hash) por identidad
   * de valor evita recalcular AES/HMAC repetidamente sin estado compartido mutable.
   */
  private static final ThreadLocal<Memo> MEMO = ThreadLocal.withInitial(Memo::new);

  private static final class Memo {
    String value;
    String encrypt;
    String hash;
  }

  /**
   * Columnas al guardar. Orden alfabetico del embeddable: 0 encrypt,
   * 1 hash (null si no searchable o valor null), 2 legacy (dual-write en claro).
   */
  @Override
  public Object getPropertyValue(String component, int property) {
    if (component == null) return null;
    try {
      if (property == 2) return component; // legacy dual-write: no requiere cripto
      SealedCodec codec = SealedRegistry.codec();
      Memo m = MEMO.get();
      if (m.value != component) {
        m.value = component;
        m.encrypt = codec.sealEncrypt(component, domain);
        m.hash = searchable ? codec.hashOnly(component, domain) : null;
      }
      return switch (property) {
        case 0 -> m.encrypt;
        case 1 -> m.hash;
        case 2 -> component;
        default -> throw new HibernateException("SealedCompositeType: propiedad " + property + " fuera de [0,2]");
      };
    } catch (HibernateException e) {
      throw e;
    } catch (Exception e) {
      throw new HibernateException("seal failed domain=" + domain, e);
    }
  }

  /** Columnas al leer. Prioridad encrypt descifrado, fallback legacy (fila aun no migrada). */
  @Override
  public String instantiate(ValueAccess values, SessionFactoryImplementor sf) {
    Object[] v = values.getValues();
    String encrypt = v.length > 0 ? (String) v[0] : null;
    String legacy = v.length > 2 ? (String) v[2] : null;
    if (encrypt == null && legacy != null) {
      SealedRegistry.signalLegacyRow(); // fila heredada: el listener la sellara
    }
    try {
      return SealedRegistry.codec().fromColumns(legacy, encrypt, domain);
    } catch (Exception e) {
      throw new HibernateException("unseal failed domain=" + domain, e);
    }
  }
}
