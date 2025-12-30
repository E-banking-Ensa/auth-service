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
}

