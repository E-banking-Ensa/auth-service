package org.example.microservice.authservice.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import org.example.microservice.authservice.enums.UserRole;

import java.util.List;

// DTO for signup payload
@Getter
public class SignupRequest {
    @NotBlank
    private String username;
    @Email
    private String email;
    @NotBlank
    private String firstName;
    @NotBlank
    private String lastName;
    @NotBlank
    private String password;
    @NotBlank
    String phoneNumber;
    @NotBlank
    String address;
    @NotBlank
    private List<String> roles;

    public SignupRequest(String email,List<String> roles, String firstName, String lastName, String password, String phoneNumber, String address) {
        this.username = firstName+" "+ lastName+ " " +email ;
        this.email = email;
        this.firstName = firstName;
        this.lastName = lastName;
        this.password = password;
        this.phoneNumber = phoneNumber;
        this.address = address;
        this.roles = roles;
    }

}
