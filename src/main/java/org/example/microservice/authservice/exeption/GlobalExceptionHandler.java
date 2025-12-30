package org.example.microservice.authservice.exeption;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.client.HttpClientErrorException;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.HashMap;
import java.util.Map;

@ControllerAdvice
public class GlobalExceptionHandler {

    private final ObjectMapper mapper = new ObjectMapper();

    // map Keycloak HTTP errors to a clean JSON body
    @ExceptionHandler(HttpClientErrorException.class)
    public ResponseEntity<?> handleHttpClientError(HttpClientErrorException ex) {
        Map<String, Object> body = tryParseJson(ex.getResponseBodyAsString());
        if (body.isEmpty()) {
            body.put("error", ex.getStatusText());
            body.put("message", ex.getResponseBodyAsString());
        }
        return ResponseEntity.status(ex.getStatusCode()).body(body);
    }

    // fallback for unhandled errors
    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleGeneric(Exception ex) {
        Map<String, Object> body = new HashMap<>();
        body.put("error", "internal_error");
        body.put("message", ex.getMessage());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
    }

    private Map<String,Object> tryParseJson(String input) {
        try {
            if (input == null || input.isBlank()) return new HashMap<>();
            return mapper.readValue(input, Map.class);
        } catch (Exception e) {
            return new HashMap<>();
        }
    }
}
