package org.example.microservice.authservice.dto;

import java.net.URI;

// simple user reference (email-based lookup of real Keycloak id)
public class UserRef {
    private final String email;
    private final URI location;

    public UserRef(String email, URI location) {
        this.email = email;
        this.location = location;
    }

    // returns the email used to create / identify the user
    public String getEmail() {
        return email;
    }

    public URI getLocation() {
        return location;
    }
}
