package org.example.microservice.authservice.client;

import org.example.microservice.authservice.dto.UserServiceUser;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(name = "user-service")
public interface UserServiceClient {

    @PostMapping("/api/v1/users/internal/sync")
    void createUser(@RequestBody UserServiceUser user);
}

