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

import com.google.crypto.tink.Aead;
import java.security.GeneralSecurityException;
import java.util.Base64;
import javax.sql.DataSource;
import org.h2.jdbcx.JdbcDataSource;
import org.junit.jupiter.api.Test;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

/** La auto-config levanta beans desde props + Aead aportado, con DataSource H2. */
class SealedSpringAutoConfigurationTest {

  private final ApplicationContextRunner runner = new ApplicationContextRunner()
      .withConfiguration(AutoConfigurations.of(SealedSpringAutoConfiguration.class));

  static final class FakeAead implements Aead {
    @Override public byte[] encrypt(byte[] plain, byte[] aad) throws GeneralSecurityException {
      byte[] out = new byte[plain.length + 1];
      out[0] = (byte) plain.length;
      System.arraycopy(plain, 0, out, 1, plain.length);
      return out;
    }
    @Override public byte[] decrypt(byte[] cipher, byte[] aad) throws GeneralSecurityException {
      int n = cipher[0];
      byte[] out = new byte[n];
      System.arraycopy(cipher, 1, out, 0, n);
      return out;
    }
  }

  @Test
  void contextLoadsAndExposesSealBeans() {
    String pepper = Base64.getEncoder().encodeToString(new byte[32]);
    JdbcDataSource ds = new JdbcDataSource();
    ds.setURL("jdbc:h2:mem:springseal;DB_CLOSE_DELAY=-1");
    ds.setUser("sa");
    runner.withPropertyValues("seal.pepper-b64=" + pepper, "seal.version=v1")
        .withBean(Aead.class, FakeAead::new)
        .withBean(DataSource.class, () -> ds)
        .run(ctx -> {
          assertThat(ctx).hasSingleBean(BlindIndexer.class);
          assertThat(ctx).hasSingleBean(Sealer.class);
          assertThat(ctx).hasSingleBean(SealedCodec.class);
          assertThat(ctx).hasSingleBean(SealedConfig.class);
          assertThat(ctx).hasSingleBean(ApplicationRunner.class);
          assertThat(ctx).hasSingleBean(SealedSpringBootstrap.class);
          BlindIndexer idx = ctx.getBean(BlindIndexer.class);
          assertThat(idx.hash("Hola@X.com ", "d")).isEqualTo(idx.hash("hola@x.com", "d"));
        });
  }

  @Test
  void missingPepperFailsFast() {
    String pepper = Base64.getEncoder().encodeToString(new byte[32]);
    JdbcDataSource ds = new JdbcDataSource();
    ds.setURL("jdbc:h2:mem:springsealnopep;DB_CLOSE_DELAY=-1");
    ds.setUser("sa");
    runner.withPropertyValues("seal.version=v1") // sin seal.pepper-b64
        .withBean(Aead.class, FakeAead::new)
        .withBean(DataSource.class, () -> ds)
        .run(ctx -> {
          assertThat(ctx).hasFailed();
          assertThat(ctx.getStartupFailure())
              .hasStackTraceContaining("Falta seal.pepper-b64");
        });
  }

  @Test
  void missingAeadFailsBecauseCodecNeedsSealer() {
    String pepper = Base64.getEncoder().encodeToString(new byte[32]);
    runner.withPropertyValues("seal.pepper-b64=" + pepper, "seal.version=v1")
        .run(ctx -> {
          // Sin Aead no hay Sealer, y SealedCodec lo exige: arranque fail-fast
          // (la app DEBE aportar el bean Aead/Tink).
          assertThat(ctx).hasFailed();
          assertThat(ctx.getStartupFailure()).hasStackTraceContaining("Sealer");
        });
  }

  @Test
  void emptyEntitiesStartsAndBootstrapIsNoOp() {
    String pepper = Base64.getEncoder().encodeToString(new byte[32]);
    JdbcDataSource ds = new JdbcDataSource();
    ds.setURL("jdbc:h2:mem:springsealempty;DB_CLOSE_DELAY=-1");
    ds.setUser("sa");
    runner.withPropertyValues("seal.pepper-b64=" + pepper,
            "seal.version=v1", "seal.entities=") // lista vacia
        .withBean(Aead.class, FakeAead::new)
        .withBean(DataSource.class, () -> ds)
        .run(ctx -> {
          assertThat(ctx).hasSingleBean(ApplicationRunner.class);
          // Sin entidades el bootstrap es no-op (no falla, no migra nada)
          assertThat(ctx.getBean(SealedSpringBootstrap.class).run().migrated()).isEmpty();
        });
  }

  @Test
  void exportPathWritesFlywayFileOnStartup() throws Exception {
    String pepper = Base64.getEncoder().encodeToString(new byte[32]);
    JdbcDataSource ds = new JdbcDataSource();
    String db = "jdbc:h2:mem:springsealexport" + System.nanoTime() + ";DB_CLOSE_DELAY=-1";
    ds.setURL(db);
    ds.setUser("sa");
    // Tabla legacy pre-creada para que haya DDL pendiente que exportar
    try (java.sql.Connection cn = ds.getConnection(); java.sql.Statement st = cn.createStatement()) {
      st.execute("CREATE TABLE customers(id BIGINT PRIMARY KEY, email VARCHAR(255))");
    }
    java.nio.file.Path out = java.nio.file.Files.createTempFile("libseal-export", ".sql");
    runner.withPropertyValues(
            "seal.pepper-b64=" + pepper,
            "seal.version=v1",
            "seal.schema-mode=VALIDATE_EXPORT",
            "seal.export-path=" + out.toAbsolutePath(),
            "seal.entities=" + ExportedCustomer.class.getName())
        .withBean(Aead.class, FakeAead::new)
        .withBean(DataSource.class, () -> ds)
        .run(ctx -> {
          assertThat(ctx).hasNotFailed();
          // ApplicationRunner no corre en ApplicationContextRunner: invocamos el bootstrap.
          ctx.getBean(SealedSpringBootstrap.class).run();
        });
    String sql = java.nio.file.Files.readString(out);
    assertThat(sql).contains("libseal").contains("email_se").contains("email_sh");
  }
}
