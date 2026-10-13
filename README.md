# Cifrado de campos en reposo para JPA/Panache

Cifra campos `String` en base de datos con AES-GCM y permite buscarlos por igualdad exacta mediante índice ciego HMAC. Funciona con cualquier base relacional. Las claves se montan desde el cluster vía `application.yaml`/env (SecretManager, K8s, otros).

## Módulos

```
lib-seal/
  libseal-core/         // API y criptografía, sin framework (agnóstico javax/jakarta)
  libseal-hibernate6/   // CompositeUserType para Hibernate 6 (jakarta)
  libseal-hibernate5/   // CompositeUserType para Hibernate 5.6 (javax)
  libseal-quarkus/      // integración Panache Quarkus 3 (jakarta)
  libseal-quarkus2/     // integración Panache Quarkus 2.13 (javax, perfil -Pquarkus2)
  libseal-spring/       // auto-configuración Spring Boot 3 (reusa core)
```

| App | Dependencias |
|---|---|
| Quarkus 3 | `libseal-quarkus` + `libseal-hibernate6` |
| Quarkus 2.13 | `libseal-quarkus2` + `libseal-hibernate5` |
| Spring Boot 3 | `libseal-spring` |

En ambas ramas los nombres físicos (`email/email_se/email_sh`), el DDL y la migración son idénticos: una BBDD sellada con una rama la lee la otra. El dominio viaja en subclase por campo en las dos ramas (`@CompositeType`/`@Type` no reciben parámetros de anotación en ningún major).

## Instalación (Quarkus)

```xml
<dependency><groupId>libseal</groupId><artifactId>libseal-quarkus</artifactId><version>0.1.0-SNAPSHOT</version></dependency>
```

Declara las claves una vez en tu app:

```java
@ApplicationScoped
public class SealBeans {
  @Produces @ApplicationScoped Sealer sealer(ConfigKeyProvider keys) throws Exception {
    Aead aead = /* keyset Tink resuelto al arrancar desde SEAL_DEK_B64 + kek-uri */;
    return new TinkSealer(aead, keys.version());
  }
  @Produces @ApplicationScoped BlindIndexer indexer(ConfigKeyProvider keys) {
    return new HmacBlindIndexer(keys.pepperBytes(), keys.version());
  }
}
```

Alternativa en una linea: `SealedKeys.from(keyProvider)` devuelve `Beans(sealer, indexer)` a partir de un `KeyProvider` (`ConfigKeyProvider` lee `SEAL_PEPPER_B64`/version del cluster).

El arranque (reconcile DDL + backfill STRICT + purga legacy + registro LAZY) es automatico: `SealedBootstrap` escucha el `StartupEvent` y ejecuta `SealedRuntime.run`. Solo declara las entidades gestionadas:

```java
@ApplicationScoped
public class MisEntidades implements SealedEntitySource {
  public List<Class<?>> sealedEntities() { return List.of(Customer.class, Contact.class); }
}
```

Sin ningun `SealedEntitySource` el arranque es no-op. Las props `seal.*` se leen de MicroProfile Config.

`application.yaml`:

```yaml
seal:
  pepper-b64: ${SEAL_PEPPER_B64}
  pepper-version: v1
  dek-keyset-b64: ${SEAL_DEK_B64}
  kek-uri: gcp-kms://projects/P/locations/global/keyRings/app/cryptoKeys/field-kek-v1
  schema-mode: UPDATE            # VALIDATE | UPDATE | VALIDATE_EXPORT
  migration-default: LAZY        # DISABLED | LAZY | STRICT | STRICT_LAZY
  batch-size: 500
  drop-legacy: false
  strict-locking: true           # false en motores sin FOR UPDATE SKIP LOCKED (p. ej. H2)
  export-path: build/libseal.sql # opcional: escribe el DDL Flyway pendiente al arrancar
  # entities: [com.acme.Customer]  # (solo Spring) FQCN de las clases @SealedEntity
```

Valores inválidos o en blanco de `schema-mode`/`migration-default`/`batch-size` caen al default sin romper el arranque (`SealedConfig.parse`).

## Convención de columnas

Por defecto, un campo `email` usa 3 columnas físicas:

| Rol | Columna | Contenido |
|---|---|---|
| `legacy` | `email` | plano heredado (solo lectura/migración, se purga con `drop-legacy`) |
| `encrypt` | `email_se` (`se` = sealed-encrypt) | `v1:base64(AES-GCM(plain, aad=domain))` |
| `hash` | `email_sh` (`sh` = sealed-hash) | `v1:hex(HMAC(pepper, "domain\|normalize(value)"))` |

Override híbrido por campo (opcional): `@Sealed(domain="...", encrypt="...", hash="...", legacy="...", searchable=...)`. Con `searchable=false` no se crea ni mantiene `*_sh`.

El **orden lógico** de las 3 columnas difiere entre ramas, pero el **esquema físico y los nombres son idénticos** (por eso una BBDD sellada por una rama la lee la otra):

| Rama | API de mapeo | Orden de columnas |
|---|---|---|
| Hibernate 6 (jakarta) | `@CompositeType` + `@AttributeOverrides` | `[encrypt, hash, legacy]` |
| Hibernate 5 (javax) | `@Type` + `@Columns` | `[legacy, encrypt, hash]` |

**Invariante de `@Id`:** la PK debe declararse en la **propia clase** de la entidad (o heredarse), con `@Id`; si usas `@Column(name=...)` se respeta el nombre físico. libseal distingue el nombre del **campo Java** (para reflexión, p. ej. el resealer LAZY) del nombre de **columna** (para SQL). `@SealedEntity` es `@Inherited`: puede declararse en una superclase.

## Uso en la entidad

Añade `@Sealed` al campo. No necesitas declarar columnas adicionales en Java:

```java
import libSeal.Sealed;
import libSeal.SealedEntity;
import libSeal.SealedMigration;
import libSeal.SealedEntityListener;
import libSeal.SealedCompositeType;
import org.hibernate.annotations.CompositeType;
import jakarta.persistence.AttributeOverride;
import jakarta.persistence.AttributeOverrides;

// Hibernate 6: @CompositeType no acepta parametros; dominio via subclase por campo.
public static class EmailType extends SealedCompositeType {
  public EmailType() { super("customer.email", true); }
}

@SealedEntity(domain="customer", migration=SealedMigration.LAZY)
@EntityListeners(SealedEntityListener.class)
@Entity
@Table(name="customers")
public class Customer extends PanacheEntity {

  @CompositeType(EmailType.class)
  @AttributeOverrides({
    @AttributeOverride(name="encrypt", column=@Column(name="email_se", length=2048)),
    @AttributeOverride(name="hash", column=@Column(name="email_sh", length=128)),
    @AttributeOverride(name="legacy", column=@Column(name="email"))
  })
  @Sealed(domain="customer.email")
  public String email;
}
```

En Java sigues trabajando con texto en claro. En base de datos se guardan la columna cifrada y la columna de búsqueda. Si la tabla ya tenía `email` en claro, la librería crea las columnas que falten y migra los datos según el modo configurado.

Nombres de columna personalizados (opcional):

```java
@Sealed(domain="customer.email", encrypt="c_email_se", hash="c_email_sh", legacy="c_email", searchable=true)
```

Con `searchable=false` el campo se cifra pero no se puede buscar por él.

### Variante Quarkus 2.13 (Hibernate 5 / javax)

Misma API con imports `javax.persistence.*`:

```java
public static class EmailType extends SealedCompositeType {
  public EmailType() { super("customer.email", true); }
}

@Type(type = "com.tuapp.EmailType")
@Columns(columns = {
  @Column(name = "email"),
  @Column(name = "email_se", length = 2048),
  @Column(name = "email_sh", length = 128)
})
@Sealed(domain = "customer.email")
public String email;
```

(El orden de `@Columns` debe ser `[legacy, encrypt, hash]`; en Hibernate 6 se usa `@AttributeOverrides` en su lugar.)

## Buscar por un campo sellado

En tu repositorio:

```java
@ApplicationScoped
public class UsuarioRepository implements PanacheSealedRepository<Usuario> {
  public Optional<Usuario> findByEmail(String email) {
    return findSealed("email", email);
  }
}
```

Sin repositorio:

```java
SealedPanache.findSealed(Usuario.class, "email", email);
```

La búsqueda es por igualdad exacta. No admite `LIKE`, rangos ni ordenación sobre el campo sellado. Para unicidad, declara el `unique` sobre la columna de búsqueda (`email_sh`).

## Esquema y migración

- `seal.schema-mode=UPDATE` crea las columnas e índices que falten. `VALIDATE` solo comprueba (y falla si hay pendiente). `VALIDATE_EXPORT` genera el SQL para aplicarlo con Flyway/Liquibase.
- `migration=LAZY` (defecto): cada fila se sella al leerla o escribirla, sin cortes. Solo cuando la fila leída venía **sin sellar** (`*_se IS NULL` con legacy presente) el listener la re-sella en el acto mediante un `UPDATE` explícito (`SealedResealer`), sin depender del dirty-check de Hibernate. Filas ya selladas **no** provocan escrituras extra. Requiere el `DataSource` (lo aporta el arranque); el `UPDATE` es idempotente (`AND *_se IS NULL`).
- `migration=STRICT`: sella todo al arrancar, por lotes, **todos los campos sellados** de cada tabla (un dominio/AAD por campo). Idempotente (`AND email_se IS NULL`), reanudable y multi-instancia (`FOR UPDATE SKIP LOCKED` donde el motor lo soporta; desactivable con `strict-locking: false` para H2). Combinable como `STRICT_LAZY`.
- `drop-legacy: true` **purga** la columna original (`ALTER TABLE ... DROP COLUMN`) solo cuando el backfill de ese campo está completo (ninguna fila con legacy no nulo y `*_se` nulo). Si queda alguna sin sellar, no la elimina.

Export Flyway (solo `ADD`, nunca `DROP`):

```java
SealedSchemaReconciler rec = new SealedSchemaReconciler(ds, config);
String sql = rec.exportFlyway(SealedModels.toReconciler(models));
Files.writeString(migrationsDir.resolve("V3__libseal.sql"), sql);
```

O al arrancar, sin código: define `seal.export-path` y libseal escribe el DDL pendiente
(`SealedRuntime.exportFlyway`) antes de aplicar nada. El SQL generado se aplica con Flyway
real y luego `schema-mode=VALIDATE` pasa (cubierto por test).

## Uso con Spring Boot 3

```xml
<dependency><groupId>libseal</groupId><artifactId>libseal-spring</artifactId><version>0.1.0-SNAPSHOT</version></dependency>
<dependency><groupId>libseal</groupId><artifactId>libseal-hibernate6</artifactId><version>0.1.0-SNAPSHOT</version></dependency>
```

La entidad se mapea igual que en Quarkus 3 (subclase por campo + `@AttributeOverrides`, imports `jakarta.*`). La auto-configuración registra `Sealer`, `BlindIndexer`, `SealedCodec`, `SealedConfig`, un bean `SealedSpringBootstrap` (reconcilia + backfill STRICT + purga legacy + registra el resealer LAZY) y un `ApplicationRunner` que delega en él, desde las mismas props `seal.*`; la app solo aporta el bean Tink `Aead` y la lista `seal.entities` (FQCN) con las clases `@SealedEntity`. El bootstrap es un bean invocable, de modo que en tests se puede llamar `bootstrap.run()` sin levantar la app. Si `seal.export-path` está definido, escribe el SQL Flyway del DDL pendiente antes de aplicar nada.

```java
@Bean Aead sealDek() throws Exception {
  return /* keyset Tink resuelto al arrancar desde SEAL_DEK_B64 + kek-uri */;
}
```

Búsqueda exacta sin ver la columna hash (bean auto-registrado si hay `EntityManager`):

```java
@Service
public class Usuarios {
  private final SealedFinder finder;
  public Usuarios(SealedFinder finder) { this.finder = finder; }
  public Optional<Usuario> porEmail(String email) {
    return finder.find(Usuario.class, "email", email);
  }
}
```

Sin `EntityManager` como bean, declarar manual: `@Bean SealedFinder sealedFinder(@PersistenceContext EntityManager em, BlindIndexer i)`.

## Compilación nativa

Registra entidad y repositorio para reflexión:

```java
import io.quarkus.runtime.annotations.RegisterForReflection;

@RegisterForReflection(targets = { Usuario.class, UsuarioRepository.class })
@ApplicationScoped
public class UsuarioRepository implements PanacheSealedRepository<Usuario> {
  public Optional<Usuario> findByEmail(String email) {
    return findSealed("email", email);
  }
}
```

## Rotación de claves

Los valores guardan prefijo de versión (`v1:`). Para rotar, publica la versión nueva (`v2`); lo nuevo se escribe con ella y lo anterior se sigue leyendo hasta que un job lo re-sella. Cifrado y búsqueda rotan de forma independiente.

```java
// Cifrado: dual-read v1+v2, escritura activa
RotatingSealer sealer = new RotatingSealer(Map.of("v1", tinkV1, "v2", tinkV2), "v2");
// Búsqueda: hashes candidatos de todas las versiones → JPQL IN (encuentra filas pre-rotación)
RotatingBlindIndexer indexer = new RotatingBlindIndexer(Map.of("v1", hmacV1, "v2", hmacV2), "v2");
SealedPanache.findSealed(Usuario.class, "email", email); // IN :hashes si hay varias versiones
// Re-sellado por lotes, idempotente (solo filas con prefijo != v2):
new SealedMigrator(config, sealer, indexer).migrateReSeal(ds, models, "v2");
```

## Reglas

1. Reserva `length>=2048` para la columna cifrada y `VARCHAR(128)` para la de búsqueda.
2. `null` se guarda como `null`.
3. La búsqueda normaliza (`trim`, minúsculas, NFKC): `Hola@x.com` y `hola@x.com ` son el mismo valor.
4. Cada dominio liga el cifrado a su campo: un valor movido a otra columna o fila no abre.
5. KMS solo se usa al arrancar. Las consultas cifran en local, sin llamadas por query.

## Licencia

AGPL-3.0-only, Copyright (C) 2026 aFE. Ver `LICENSE` (texto íntegro) y `NOTICE` (términos adicionales §7.b de preservación de autoría: toda obra derivada debe conservar la cabecera de copyright y la atribución `libseal — Copyright (C) 2026 aFE`).
