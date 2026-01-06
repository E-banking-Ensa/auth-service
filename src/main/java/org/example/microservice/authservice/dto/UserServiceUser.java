package org.example.microservice.authservice.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.example.microservice.authservice.enums.UserRole;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserServiceUser {
    @NotBlank String username;
    @NotBlank
    @Email
    String email;
    int age;
    @NotBlank String firstName;
    @NotBlank String lastName;
    @NotBlank String phoneNumber;
    @NotNull
    UserRole role;
    String adresse; // Matches 'adresse' in user-service DTO
}
