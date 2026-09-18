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

    /**
     * How long an EXPIRED, never-revoked token row is kept before the purge
     * deletes it, in days past its own expiry.
     *
     * <p>Rotation mints a successor on every refresh and marks the predecessor
     * used, so this table gains a row per refresh and, until the purge existed,
     * never lost one. It is the fastest-growing table in the schema.
     *
     * <p>Seven days past expiry rather than zero: an expired row is still
     * evidence when someone asks what happened last week, and nothing reads it
     * for authentication once {@code expiresAt} has passed.
     */
    private int purgeAfterExpiryDays = 7;
}
