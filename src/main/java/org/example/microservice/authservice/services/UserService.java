package org.example.microservice.authservice.services;

import org.example.microservice.authservice.dto.SignupRequest;
import org.example.microservice.authservice.dto.UserRef;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@Service
public class UserService {
    private final RestTemplate rest = new RestTemplate();
    private final KeycloakAdminClient kc;

    public UserService(KeycloakAdminClient kc) {
        this.kc = kc;
    }

    // create user and return id + location
    public UserRef createUser(SignupRequest signup, String adminToken) {
        String kcBase = kc.getBaseUrl();
        String url = kcBase + "/admin/realms/" + kc.getRealm() + "/users";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(adminToken);

        Map<String, Object> payload = new HashMap<>();
        payload.put("username", signup.getUsername());
        payload.put("email", signup.getEmail());
        payload.put("firstName", signup.getFirstName());
        payload.put("lastName", signup.getLastName());
        payload.put("enabled", true);
        payload.put("emailVerified", false);
        payload.put("credentials", new Object[]{ Map.of("type","password","value",signup.getPassword(),"temporary",false)});

        HttpEntity<Map<String,Object>> entity = new HttpEntity<>(payload, headers);
        ResponseEntity<Void> resp = rest.postForEntity(URI.create(url), entity, Void.class);
        URI loc = resp.getHeaders().getLocation();

        String userId = null;
        if (loc != null) {
            String path = loc.getPath();
            int idx = path.lastIndexOf('/');
            if (idx > -1 && idx + 1 < path.length()) userId = path.substring(idx + 1);
        }
        if (userId == null || userId.isBlank()) {
            userId = findUserIdByUsername(signup.getUsername(), adminToken);
        }
        return new UserRef(userId, loc);
    }

    // query user by username to get id
    public String findUserIdByUsername(String username, String adminToken) {
        String kcBase = kc.getBaseUrl();
        String url = kcBase + "/admin/realms/" + kc.getRealm() + "/users?username=" + username;
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(adminToken);
        HttpEntity<Void> entity = new HttpEntity<>(headers);
        ResponseEntity<List> resp = rest.exchange(URI.create(url), HttpMethod.GET, entity, List.class);
        if (resp.getBody() != null && !resp.getBody().isEmpty()) {
            Object first = resp.getBody().get(0);
            if (first instanceof Map<?,?> map && map.get("id") != null) {
                return Objects.toString(map.get("id"));
            }
        }
        return null;
    }
}

