package com.globus.modul26.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${myproject.jwt.secret:super-secure-random-string-change-me-please-super-long}")
    private String secret;

    //  Декодер для JWT-токенов
    @Bean
    public JwtDecoder jwtDecoder() {
        SecretKeySpec secretKey = new SecretKeySpec(secret.getBytes(), "HmacSHA256");
        return NimbusJwtDecoder.withSecretKey(secretKey).build();
    }

    //  Шифратор для паролей
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // ⚡ Разборщик ролей из токена (claim "roles")
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter gac = new JwtGrantedAuthoritiesConverter();
        gac.setAuthoritiesClaimName("roles");
        gac.setAuthorityPrefix("ROLE_"); // для .hasRole("ADMIN") и т.п.

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(gac);
        return converter;
    }

    // 🛡 НастрЙки доступа и аутентификации
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeHttpRequests(authz -> authz

                        .requestMatchers(
                                "/swagger-ui/**",
                                "/swagger-ui.html",
                                "/v3/api-docs/**",
                                "/swagger-resources/**",
                                "/swagger/api-docs/**",
                                "/webjars/**",
                                "/doc.html"
                        ).permitAll()
                        // 👇 Открываем регистрацию/логин
                        .requestMatchers(
                                "/api/auth/register",
                                "/api/auth/login"
                        ).permitAll()
                        // 👇 ОТКРЫВАЕМ ДЛЯ PROMETHEUS
                        .requestMatchers("/actuator/prometheus").permitAll()
                        // 👇 Доступы к API логирования
                        .requestMatchers("/api/logs/user/**").hasAnyRole("ADMIN", "USER")
                        .requestMatchers("/api/logs/suspicious").hasRole("ADMIN")
                        .requestMatchers("/api/logs/event").hasAnyRole("ADMIN", "USER")
                        // 👇 Всё остальное — только авторизированным
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 ->
                        oauth2.jwt(jwt ->
                                jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())
                        )
                );
        return http.build();
    }

    //  Фильтр для логирования b заголовка Authorization
    @Bean
    public FilterRegistrationBean<OncePerRequestFilter> logHeadersFilter() {
        FilterRegistrationBean<OncePerRequestFilter> bean = new FilterRegistrationBean<>();
        bean.setFilter(new OncePerRequestFilter() {
            @Override
            protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
                    throws IOException, ServletException {
                System.out.println("AUTH HEADER: " + req.getHeader("Authorization"));
                chain.doFilter(req, res);
            }
        });
        bean.addUrlPatterns("/*");
        bean.setOrder(1);
        return bean;
    }
}