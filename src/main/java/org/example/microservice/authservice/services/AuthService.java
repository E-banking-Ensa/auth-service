package org.example.microservice.authservice.services;

import org.example.microservice.authservice.dto.LoginRequest;
import org.example.microservice.authservice.dto.SignupRequest;
import org.example.microservice.authservice.dto.TokenResponse;
import org.example.microservice.authservice.dto.UserRef;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.List;

// lightweight auth service that orchestrates user creation, role assignment and email verification
@Service
public class AuthService {

    private final KeycloakAdminClient keycloakAdminClient;
    private final UserService userService;
    private final RoleService roleService;
    private final EmailVerificationService emailService;

    @Value("${app.security.client-id:auth-service}")
    private String clientId;

    @Value("${app.security.client-secret:}")
    private String clientSecret;

    public AuthService(KeycloakAdminClient keycloakAdminClient,
                       UserService userService,
                       RoleService roleService,
                       EmailVerificationService emailService) {
        this.keycloakAdminClient = keycloakAdminClient;
        this.userService = userService;
        this.roleService = roleService;
        this.emailService = emailService;
    }

    // register a new user in Keycloak, assign roles and send verification email
    // now resolves the real Keycloak id using the email stored in UserRef
    public UserRef registerUser(SignupRequest signup) {
        // obtain admin token to perform realm operations
        String adminToken = keycloakAdminClient.obtainAdminAccessToken();

        // create user in Keycloak (returns email + location)
        UserRef ref = userService.createUser(signup, adminToken);

        // resolve real Keycloak user id via email
        String userId = userService.findUserIdByEmail(ref.getEmail(), adminToken);

        // assign requested roles (whitelisted by RoleService)
        List<String> mapped = roleService.mapToRealmRoles(signup.getRoles());
        if (mapped != null && !mapped.isEmpty() && userId != null && !userId.isBlank()) {
            roleService.assignRealmRoles(userId, mapped, adminToken);
        }

        // trigger email verification
        //if (userId != null && !userId.isBlank()) {
        //    emailService.sendVerificationEmail(userId, adminToken);
        //}

        return ref;
    }

    // exchange username/password for tokens at Keycloak
    public TokenResponse login(LoginRequest request) {
        if (request == null || request.getUsername() == null || request.getPassword() == null) {
            throw new IllegalArgumentException("username and password are required");
        }

        String tokenUrl = keycloakAdminClient.getBaseUrl() + "/realms/" + keycloakAdminClient.getRealm() + "/protocol/openid-connect/token";

        RestTemplate rest = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("username", request.getUsername());
        form.add("password", request.getPassword());
        form.add("client_id", clientId);
        if (clientSecret != null && !clientSecret.isBlank()) {
            form.add("client_secret", clientSecret);
        }
        if (request.getScope() != null && !request.getScope().isBlank()) {
            form.add("scope", request.getScope());
        }

        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(form, headers);
        ResponseEntity<TokenResponse> resp = rest.postForEntity(URI.create(tokenUrl), entity, TokenResponse.class);
        if (!resp.getStatusCode().is2xxSuccessful() || resp.getBody() == null) {
            throw new HttpClientErrorException(resp.getStatusCode(), "Unable to obtain token");
        }
        return resp.getBody();
    }

    // assign roles to an existing user
    public void assignRolesToUser(String userId, List<String> roles) {
        String adminToken = keycloakAdminClient.obtainAdminAccessToken();
        List<String> mapped = roleService.mapToRealmRoles(roles);
        if (mapped != null && !mapped.isEmpty()) {
            roleService.assignRealmRoles(userId, mapped, adminToken);
        }
    }

    // resend verification email
    public void resendVerification(String userId) {
        String adminToken = keycloakAdminClient.obtainAdminAccessToken();
        emailService.sendVerificationEmail(userId, adminToken);
    }
}
