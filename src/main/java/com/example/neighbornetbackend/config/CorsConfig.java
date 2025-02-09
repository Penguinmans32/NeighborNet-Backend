package com.example.neighbornetbackend.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {

    @Value("${app.frontend.url}")
    private String frontendUrl;

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();

        config.addAllowedOrigin(frontendUrl);

        config.addAllowedHeader("*");
        config.addAllowedMethod("*");

        config.setAllowCredentials(true);

        config.addExposedHeader("Cross-Origin-Opener-Policy");

        source.registerCorsConfiguration("/**", config);
        return new CorsFilter(source);
    }
}