package org.example.microservice.authservice.web;

import org.example.microservice.authservice.dto.LoginRequest;
import org.example.microservice.authservice.dto.SignupRequest;
import org.example.microservice.authservice.dto.TokenResponse;
import org.example.microservice.authservice.dto.UserRef;
import org.example.microservice.authservice.services.AuthService;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping
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
        if (ref != null && ref.getLocation() != null) headers.setLocation(ref.getLocation());
        return new ResponseEntity<>(Map.of("result", "user created"), headers, HttpStatus.CREATED);
    }
}
