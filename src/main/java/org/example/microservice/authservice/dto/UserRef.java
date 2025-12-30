package org.example.microservice.authservice.dto;

import java.net.URI;

// simple user reference
public class UserRef {
    private final String id;
    private final URI location;

    public UserRef(String id, URI location) {
        this.id = id;
        this.location = location;
    }

    public String getId() { return id; }
    public URI getLocation() { return location; }
}

