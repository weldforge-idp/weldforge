package tech.cwvermaak.weldforge.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Public liveness probe at {@code GET /health}. Always returns
 * {@code {"status":"UP"}} without touching any subsystem so external
 * monitors can confirm the API is reachable without us having to expose
 * Spring Boot Actuator's richer health details (which can leak DB/Redis
 * state) on the public ingress.
 */
@RestController
public class HealthController {

    @GetMapping("/health")
    public Map<String, String> health() {
        return Map.of("status", "UP");
    }
}
