package tech.cwvermaak.weldforge.service.security;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "app.security.refresh-token")
public class RefreshTokenProperties {

    /** Absolute token lifetime in days. */
    private int lifetimeDays = 30;
}
