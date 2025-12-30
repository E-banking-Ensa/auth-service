package org.example.microservice.authservice.web;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@Tag(name = "Auth", description = "Authentication helper endpoints for microservices")
public class AuthController {

    @GetMapping("/me")
    @Operation(summary = "Get current authenticated user claims")
    public Map<String, Object> me(Authentication authentication) {
        if (authentication.getPrincipal() instanceof Jwt jwt) {
            return jwt.getClaims();
        }
        return Map.of("principal", authentication.getName());
    }

    @GetMapping("/role/client")
    @PreAuthorize("hasRole('CLIENT')")
    @Operation(summary = "Endpoint accessible only to users with CLIENT role")
    public String clientOnly() {
        return "client-access-granted";
    }

    @GetMapping("/role/agent")
    @PreAuthorize("hasRole('AGENT')")
    @Operation(summary = "Endpoint accessible only to users with AGENT role")
    public String agentOnly() {
        return "agent-access-granted";
    }

    @GetMapping("/role/admin")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Endpoint accessible only to users with ADMIN role")
    public String adminOnly() {
        return "admin-access-granted";
    }
    
}

