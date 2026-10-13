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

import java.lang.reflect.Field;
import java.sql.DatabaseMetaData;
import java.util.ArrayList;
import java.util.List;

/**
 * Scan de @SealedEntity/@Sealed sin ensuciar DTOs: deriva columnas por convencion hibrida
 * y detecta la PK (@Id o "id") para el backfill STRICT.
  * Por cada entidad produce el DDL minimo (ADD COLUMN *_se TEXT + *_sh VARCHAR + INDEX).
 */
public final class SealedModels {
  private SealedModels() {}

  public record FieldModel(String field, Sealed ann, SealedCodec.Resolved cols) {}

  /**
   * Descriptor por entidad/tabla.
   * <ul>
   *   <li>{@code idField}: nombre del campo Java con {@code @Id} (para reflexion).</li>
   *   <li>{@code idColumn}: nombre de columna fisica (para SQL); igual a idField si no hay {@code @Column(name)}.</li>
   * </ul>
   */
  public record EntityModel(Class<?> entity, String table, String idField, String idColumn,
                            SealedMigration migration, List<FieldModel> fields) {

    /** Compat: modelos sin distincion field/column (idField == idColumn). */
    public EntityModel(Class<?> entity, String table, String idColumn,
                       SealedMigration migration, List<FieldModel> fields) {
      this(entity, table, idColumn, idColumn, migration, fields);
    }
  }

  /** Escanea clases dadas. v1 manual (la app aporta la lista, sin classpath-scanning magico). */
  public static List<EntityModel> scan(List<Class<?>> entities) {
    List<EntityModel> out = new ArrayList<>();
    for (Class<?> c : entities) {
      for (Class<?> seClass : sealedHierarchy(c)) {
        SealedEntity se = seClass.getAnnotation(SealedEntity.class);
        if (se == null) continue;
        String table = seClass.getSimpleName().toLowerCase() + "s";
        // Agnóstico javax/jakarta: se lee por nombre para no importar ninguna de las dos APIs.
        String tableName = stringMember(annotationByName(seClass, "jakarta.persistence.Table", "javax.persistence.Table"), "name");
        if (tableName != null && !tableName.isEmpty()) table = tableName;

        String idField = "id";
        String idColumn = "id";
        Field idFound = null;
        for (Field f : hierarchyFields(seClass)) {
          if (annotationByName(f, "jakarta.persistence.Id", "javax.persistence.Id") != null) {
            idField = f.getName();
            idColumn = f.getName();
            String colName = stringMember(
                annotationByName(f, "jakarta.persistence.Column", "javax.persistence.Column"), "name");
            if (colName != null && !colName.isEmpty()) idColumn = colName;
            idFound = f;
            break;
          }
        }
        List<FieldModel> fs = new ArrayList<>();
        for (Field f : hierarchyFields(seClass)) {
          Sealed ann = f.getAnnotation(Sealed.class);
          if (ann != null) {
            // El id nunca se sella aunque lleve @Sealed por error de configuracion.
            if (idFound != null && f.getName().equals(idFound.getName())) continue;
            fs.add(new FieldModel(f.getName(), ann, SealedCodec.resolve(f.getName(), ann)));
          }
        }
        out.add(new EntityModel(seClass, table, idField, idColumn, se.migration(), fs));
      }
    }
    return out;
  }

  /**
   * Sube la jerarquia desde {@code c} hasta (e incluyendo) la primera clase con
   * {@code @SealedEntity}; cubre entidades cuyo tag vive en una superclase.
   */
  static List<Class<?>> sealedHierarchy(Class<?> c) {
    List<Class<?>> chain = new ArrayList<>();
    for (Class<?> cur = c; cur != null && cur != Object.class; cur = cur.getSuperclass()) chain.add(cur);
    for (Class<?> cur : chain) {
      if (cur.getAnnotation(SealedEntity.class) != null) return List.of(cur);
    }
    return chain.isEmpty() ? List.of(c) : List.of(chain.get(chain.size() - 1));
  }

  /** Campos de toda la jerarquia (subclase primero), incluye heredados de superclases. */
  static List<Field> hierarchyFields(Class<?> c) {
    List<Field> out = new ArrayList<>();
    for (Class<?> cur = c; cur != null && cur != Object.class; cur = cur.getSuperclass()) {
      for (Field f : cur.getDeclaredFields()) out.add(f);
    }
    return out;
  }

  /** Convierte EntityModels a modelos del reconciliador (solo ADD, agnostico). */
  public static List<SealedSchemaReconciler.SealedModel> toReconciler(List<EntityModel> models) {
    List<SealedSchemaReconciler.SealedModel> out = new ArrayList<>();
    for (EntityModel m : models) {
      out.add(new SealedSchemaReconciler.SealedModel() {
        @Override public String table() { return m.table(); }
        @Override public List<String> requiredDdl(DatabaseMetaData md) throws Exception {
          List<String> ddl = new ArrayList<>();
          for (FieldModel f : m.fields()) {
            if (!SealedSchemaReconciler.hasColumn(md, m.table(), f.cols().encryptCol()))
              ddl.add("ALTER TABLE " + m.table() + " ADD COLUMN " + f.cols().encryptCol() + " TEXT");
            if (f.cols().hashCol() != null && !SealedSchemaReconciler.hasColumn(md, m.table(), f.cols().hashCol())) {
              ddl.add("ALTER TABLE " + m.table() + " ADD COLUMN " + f.cols().hashCol() + " VARCHAR(128)");
              ddl.add("CREATE INDEX idx_" + m.table() + "_" + f.cols().hashCol() + " ON " + m.table() + "(" + f.cols().hashCol() + ")");
            }
          }
          return ddl;
        }
      });
    }
    return out;
  }

  /**
   * Busca una anotación por nombre binario (p.ej. {@code jakarta.persistence.Table}
   * o {@code javax.persistence.Table}) sin importar su API. Así el core sirve a
   * apps Hibernate 5 (javax) y 6 (jakarta) sin dependencias de persistencia.
   */
  static java.lang.annotation.Annotation annotationByName(
      java.lang.reflect.AnnotatedElement e, String... binaryNames) {
    for (java.lang.annotation.Annotation a : e.getAnnotations()) {
      String n = a.annotationType().getName();
      for (String want : binaryNames) {
        if (n.equals(want)) return a;
      }
    }
    return null;
  }

  /** Lee un miembro String (p.ej. {@code name}) de una anotación hallada por nombre. */
  static String stringMember(java.lang.annotation.Annotation a, String member) {
    if (a == null) return null;
    try {
      Object v = a.annotationType().getMethod(member).invoke(a);
      return (v instanceof String) ? (String) v : null;
    } catch (Exception ignored) {
      return null;
    }
  }
}
