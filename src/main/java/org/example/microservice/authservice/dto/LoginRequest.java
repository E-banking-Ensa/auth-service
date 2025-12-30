package org.example.microservice.authservice.dto;

// DTO for login payload
public class LoginRequest {
    private String username;
    private String password;
    private String scope;

    public LoginRequest() {}

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }

    public String getScope() { return scope; }
    public void setScope(String scope) { this.scope = scope; }
}
