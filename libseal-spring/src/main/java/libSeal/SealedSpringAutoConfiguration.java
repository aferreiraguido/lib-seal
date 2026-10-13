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

import com.google.crypto.tink.Aead;
import java.util.Base64;
import java.util.List;
import javax.sql.DataSource;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Auto-configuracion Spring Boot. Reusa libseal-core (mismo reconciliador y
 * migrador que Quarkus). La app aporta un bean {@link Aead} (Tink) y, si usa
 * base de datos, el {@link DataSource} habitual.
 */
@AutoConfiguration
@ConditionalOnClass(SealedCodec.class)
@EnableConfigurationProperties(SealedSpringProperties.class)
public class SealedSpringAutoConfiguration {

  @Bean
  @ConditionalOnMissingBean
  public BlindIndexer sealBlindIndexer(SealedSpringProperties props) {
    if (props.getPepperB64() == null) throw new IllegalStateException("Falta seal.pepper-b64");
    return new HmacBlindIndexer(Base64.getDecoder().decode(props.getPepperB64()), props.getVersion());
  }

  @Bean
  @ConditionalOnMissingBean
  public SealedConfig sealConfig(SealedSpringProperties props) {
    return SealedConfig.parse(props.getSchemaMode(), props.getMigrationDefault(),
        props.getBatchSize(), props.isDropLegacy(), props.isStrictLocking());
  }

  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnBean(Aead.class)
  public Sealer sealSealer(Aead dek, SealedSpringProperties props) {
    return new TinkSealer(dek, props.getVersion());
  }

  @Bean
  @ConditionalOnMissingBean
  public SealedCodec sealCodec(Sealer sealer, BlindIndexer indexer) {
    SealedRegistry.init(sealer, indexer);
    return new SealedCodec(sealer, indexer);
  }

  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnBean(jakarta.persistence.EntityManager.class)
  public SealedFinder sealFinder(jakarta.persistence.EntityManager em, BlindIndexer indexer) {
    return new SealedFinder(em, indexer);
  }

  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnBean(DataSource.class)
  public SealedSpringBootstrap sealedSpringBootstrap(DataSource ds, SealedConfig config,
                                                     Sealer sealer, BlindIndexer indexer,
                                                     SealedSpringProperties props) {
    return new SealedSpringBootstrap(ds, config, sealer, indexer, props);
  }

  @Bean
  @ConditionalOnMissingBean
  @ConditionalOnBean(SealedSpringBootstrap.class)
  public ApplicationRunner sealBootstrap(SealedSpringBootstrap bootstrap) {
    return args -> bootstrap.run();
  }
}
