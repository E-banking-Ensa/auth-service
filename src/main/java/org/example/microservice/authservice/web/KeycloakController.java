package org.example.microservice.authservice.web;

import org.example.microservice.authservice.dto.LoginRequest;
import org.example.microservice.authservice.dto.SignupRequest;
import org.example.microservice.authservice.dto.TokenResponse;
import org.example.microservice.authservice.dto.UserRef;
import org.example.microservice.authservice.services.AuthService;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/auth")
@CrossOrigin(origins = "*", allowedHeaders = "*", methods = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE, RequestMethod.OPTIONS})
public class KeycloakController {

    private final AuthService authService;

    public KeycloakController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping(path = "/login", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        if (request.getUsername() == null || request.getPassword() == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "username and password are required"));
        }
        TokenResponse tokens = authService.login(request);
        return ResponseEntity.ok(tokens);
    }

    @PostMapping(path = "/logup", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> register(@RequestBody SignupRequest signup) {
        if (signup.getUsername() == null || signup.getPassword() == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "username and password are required"));
        }

        UserRef ref = authService.registerUser(signup);

        HttpHeaders headers = new HttpHeaders();
        if (ref != null && ref.location() != null) headers.setLocation(ref.location());
        return new ResponseEntity<>(Map.of("result", "user created"), headers, HttpStatus.CREATED);
    }

    // logout endpoint: revokes refresh token in Keycloak
    @PostMapping(path = "/logout")
    public ResponseEntity<?> logout(@RequestHeader(name = "X-Refresh-Token", required = false) String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "X-Refresh-Token header is required"));
        }

        authService.logout(refreshToken);
        return ResponseEntity.ok(Map.of("result", "user logged out"));
    }

    // trigger a password recovery email using Keycloak
    @PostMapping(path = "/password/recover", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> recoverPassword(@RequestBody Map<String, String> body) {
        String email = body.get("email");
        if (email == null || email.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "email is required"));
        }

        authService.sendPasswordRecovery(email);
        return ResponseEntity.ok(Map.of("result", "password recovery email sent"));
    }
}
