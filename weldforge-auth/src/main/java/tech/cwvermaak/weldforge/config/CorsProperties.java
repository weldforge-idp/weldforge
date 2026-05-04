package tech.cwvermaak.weldforge.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * Externalisable CORS configuration. Defaults are tuned for local
 * development; production overrides via {@code APP_CORS_ALLOWED_ORIGINS}.
 */
@ConfigurationProperties(prefix = "app.cors")
@Getter
@Setter
public class CorsProperties {

    private List<String> allowedOrigins = List.of("http://localhost:4200");
    private List<String> allowedMethods = List.of("GET", "POST", "PUT", "DELETE", "OPTIONS");
    private long maxAge = 3600;
}
