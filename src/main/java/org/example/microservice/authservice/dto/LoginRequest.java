package org.example.microservice.authservice.dto;

import lombok.Getter;
import lombok.Setter;

// DTO for login payload
@Setter
@Getter
public class LoginRequest {
    private String username;
    private String password;
    private String scope;

    public LoginRequest() {}

}
