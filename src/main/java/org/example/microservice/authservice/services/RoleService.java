package org.example.microservice.authservice.services;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class RoleService {
    private static final Logger log = LoggerFactory.getLogger(RoleService.class);

    private final RestTemplate rest = new RestTemplate();
    private final KeycloakAdminClient kc;

    public RoleService(KeycloakAdminClient kc) {
        this.kc = kc;
    }

    // map app roles to realm role names (whitelist)
    public List<String> mapToRealmRoles(List<String> roles) {
        if (roles == null) return List.of();
        Set<String> allowed = Set.of("client","agent","admin");
        return roles.stream()
                .filter(Objects::nonNull)
                .map(String::trim)
                .map(String::toLowerCase)
                .filter(allowed::contains)
                .distinct()
                .collect(Collectors.toList());
    }

    // assign realm roles to a user
    public void assignRealmRoles(String userId, List<String> roleNames, String adminToken) {
        if (userId == null || userId.isBlank()) return;
        List<Map<String,Object>> reps = new ArrayList<>();
        for (String rn : roleNames) {
            Map<String,Object> rep = fetchRoleRepresentation(rn, adminToken);
            if (rep != null) reps.add(rep);
        }
        if (reps.isEmpty()) return;

        String kcBase = kc.getBaseUrl();
        String url = kcBase + "/admin/realms/" + kc.getRealm() + "/users/" + userId + "/role-mappings/realm";
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(adminToken);
        HttpEntity<List<Map<String,Object>>> entity = new HttpEntity<>(reps, headers);

        try {
            rest.exchange(URI.create(url), HttpMethod.POST, entity, Void.class);
        } catch (RestClientException ex) {
            // log all relevant variables to help debugging
            Map<String, Object> debug = new LinkedHashMap<>();
            debug.put("userId", userId);
            debug.put("roleNames", roleNames);
            debug.put("kcBase", kcBase);
            debug.put("realm", kc.getRealm());
            debug.put("url", url);
            debug.put("adminTokenPresent", adminToken != null && !adminToken.isBlank());
            debug.put("roleRepresentations", reps);

            log.error("Failed to assign realm roles in Keycloak: {}", debug, ex);

            // rethrow with context so controller / error handler can surface it
            throw new IllegalStateException("Error assigning roles in Keycloak. Context: " + debug, ex);
        }
    }

    // read a realm role representation (id, name)
    private Map<String,Object> fetchRoleRepresentation(String roleName, String adminToken) {
        String kcBase = kc.getBaseUrl();
        String url = kcBase + "/admin/realms/" + kc.getRealm() + "/roles/" + roleName;
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(adminToken);
        HttpEntity<Void> entity = new HttpEntity<>(headers);
        ResponseEntity<Map> resp = rest.exchange(URI.create(url), HttpMethod.GET, entity, Map.class);
        Map body = resp.getBody();
        if (body == null) return null;
        Map<String,Object> rep = new HashMap<>();
        rep.put("id", body.get("id"));
        rep.put("name", body.get("name"));
        return rep;
    }
}
