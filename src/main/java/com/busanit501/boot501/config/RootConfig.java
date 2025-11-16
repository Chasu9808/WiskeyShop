package com.busanit501.boot501.config;

import jakarta.persistence.Column;
import org.modelmapper.ModelMapper;
import org.modelmapper.convention.MatchingStrategies;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RootConfig {
  @Bean
  public ModelMapper getMapper() {
    ModelMapper mapper = new ModelMapper();
    mapper.getConfiguration()
        .setFieldMatchingEnabled(true)
        .setFieldAccessLevel(org.modelmapper.config.Configuration.AccessLevel.PRIVATE)
        .setMatchingStrategy(MatchingStrategies.STRICT);
    return mapper;
  }
}








