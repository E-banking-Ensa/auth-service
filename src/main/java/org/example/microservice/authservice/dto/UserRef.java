package org.example.microservice.authservice.dto;

import java.net.URI;

 // simple user reference (email-based lookup of real Keycloak id)
public record UserRef(String email, URI location) {

}
