package org.example.microservice.authservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(
                    "/actuator/health",
                    "/actuator/info",
                    "/v3/api-docs/**",
                    "/logup",
                    "/login",
                    "/ext-login"
                ).permitAll()
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
            )
            .oauth2Login(Customizer.withDefaults());

        return http.build();
    }

    /**
     * Convert JWT claims issued by Keycloak into GrantedAuthority instances.
     * This reads roles from 'realm_access.roles' and 'resource_access.{client}.roles'.
     */
    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            // Collect roles from realm_access.roles
            Set<String> roles = Stream.of(
                    extractRealmRoles(jwt),
                    extractResourceRoles(jwt)
                )
                .flatMap(Set::stream)
                .collect(Collectors.toSet());

            if (roles.isEmpty()) {
                return Collections.emptyList();
            }

            return roles.stream()
                    .map(r -> new SimpleGrantedAuthority("ROLE_" + r.toUpperCase()))
                    .collect(Collectors.toList());
        });

        return converter;
    }

    private static Set<String> extractRealmRoles(Jwt jwt) {
        Object realmAccess = jwt.getClaims().get("realm_access");
        if (realmAccess instanceof Map) {
            Object roles = ((Map<?, ?>) realmAccess).get("roles");
            if (roles instanceof List) {
                return ((List<?>) roles).stream()
                        .filter(Objects::nonNull)
                        .map(Object::toString)
                        .collect(Collectors.toSet());
            }
        }
        return Collections.emptySet();
    }

    @SuppressWarnings("unchecked")
    private static Set<String> extractResourceRoles(Jwt jwt) {
        Object resourceAccess = jwt.getClaims().get("resource_access");
        if (resourceAccess instanceof Map) {
            Map<String, Object> ra = (Map<String, Object>) resourceAccess;
            return ra.values().stream()
                    .filter(v -> v instanceof Map)
                    .map(v -> ((Map<?, ?>) v).get("roles"))
                    .filter(r -> r instanceof List)
                    .flatMap(r -> ((List<?>) r).stream())
                    .filter(Objects::nonNull)
                    .map(Object::toString)
                    .collect(Collectors.toSet());
        }
        return Collections.emptySet();
    }

    @Bean
    public GrantedAuthoritiesMapper grantedAuthoritiesMapper() {
        SimpleAuthorityMapper authorityMapper = new SimpleAuthorityMapper();
        authorityMapper.setConvertToUpperCase(true);
        authorityMapper.setPrefix("ROLE_");
        return authorityMapper;
    }
}
