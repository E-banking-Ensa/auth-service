package org.example.microservice.authservice.dto;

import lombok.Getter;
import lombok.Setter;

import java.util.List;

// DTO for signup payload
@Setter
@Getter
public class SignupRequest {
    private String username;
    private String email;
    private String firstName;
    private String lastName;
    private String password;
    private List<String> roles;

    public SignupRequest() {}

}
