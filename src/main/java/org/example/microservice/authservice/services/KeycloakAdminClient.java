package org.example.microservice.authservice.services;

import org.example.microservice.authservice.dto.TokenResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.*;

@Service
public class KeycloakAdminClient {
    private final RestTemplate restTemplate = new RestTemplate();

    @Value("${app.security.issuer-uri}")
    private String issuerUri;

    @Value("${app.security.realm:microservice}")
    private String realm;

    @Value("${app.security.admin-client-id:admin-cli}")
    private String adminClientId;

    @Value("${app.security.admin-client-secret:}")
    private String adminClientSecret;

    // base Keycloak URL (without /realms/...)
    public String getBaseUrl() {
        return issuerUri.replaceFirst("/realms/.*$", "");
    }

    // get admin access token
    public String obtainAdminAccessToken() throws HttpClientErrorException {
        String tokenUrl = issuerUri + "/protocol/openid-connect/token";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "client_credentials");
        form.add("client_id", adminClientId);
        if (adminClientSecret != null && !adminClientSecret.isBlank()) {
            form.add("client_secret", adminClientSecret);
        }

        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(form, headers);
        ResponseEntity<TokenResponse> resp = restTemplate.postForEntity(URI.create(tokenUrl), entity, TokenResponse.class);
        if (!resp.getStatusCode().is2xxSuccessful() || resp.getBody() == null || resp.getBody().getAccessToken() == null) {
            throw new HttpClientErrorException(HttpStatus.UNAUTHORIZED, "Unable to obtain admin token");
        }
        return resp.getBody().getAccessToken();
    }

    public String getRealm() {
        return realm;
    }

    public RestTemplate getRestTemplate() {
        return restTemplate;
    }

    // Fetch user's realm-level roles from Keycloak admin REST API
    // Returns a set of role names or empty set on no roles
    public Set<String> getUserRealmRoles(String userId) {
        if (userId == null || userId.isBlank()) {
            return Collections.emptySet();
        }

        try {
            String token = obtainAdminAccessToken();
            String url = String.format("%s/admin/realms/%s/users/%s/role-mappings/realm", getBaseUrl(), realm, userId);

            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(token);
            headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

            HttpEntity<Void> entity = new HttpEntity<>(headers);

            ResponseEntity<List> resp = restTemplate.exchange(URI.create(url), HttpMethod.GET, entity, List.class);
            if (!resp.getStatusCode().is2xxSuccessful() || resp.getBody() == null) {
                return Collections.emptySet();
            }

            List<?> body = resp.getBody();
            Set<String> roles = new HashSet<>();
            for (Object item : body) {
                if (item instanceof Map) {
                    Object name = ((Map<?, ?>) item).get("name");
                    if (name != null) {
                        roles.add(name.toString());
                    }
                }
            }
            return roles;
        } catch (Exception e) {
            // propagate as runtime to be handled by caller; caller may fallback
            throw new RuntimeException("Failed to fetch user roles from Keycloak: " + e.getMessage(), e);
        }
    }
}
