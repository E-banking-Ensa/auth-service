package org.example.microservice.authservice.services;

import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.net.URI;

@Service
public class EmailVerificationService {
    private final RestTemplate rest = new RestTemplate();
    private final KeycloakAdminClient kc;

    public EmailVerificationService(KeycloakAdminClient kc) { this.kc = kc; }

    // trigger Keycloak verify-email for a user
    public void sendVerificationEmail(String userId, String adminToken) {
        if (userId == null || userId.isBlank()) return;
        String kcBase = kc.getBaseUrl();
        String url = kcBase + "/admin/realms/" + kc.getRealm() + "/users/" + userId + "/send-verify-email";
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(adminToken);
        HttpEntity<Void> entity = new HttpEntity<>(headers);
        rest.exchange(URI.create(url), HttpMethod.PUT, entity, Void.class);
    }
}

