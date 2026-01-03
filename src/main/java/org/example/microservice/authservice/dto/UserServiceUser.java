package org.example.microservice.authservice.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.example.microservice.authservice.enums.UserRole;

import java.util.UUID;

public class UserServiceUser {
    @NotBlank String username;
    @NotBlank
    @Email
    String email;
    int age;
    @NotBlank String fullName;
    @NotBlank String phoneNumber;
    @NotBlank
    UserRole role;
    String address;
}
