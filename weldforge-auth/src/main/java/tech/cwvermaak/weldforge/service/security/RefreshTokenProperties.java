package tech.cwvermaak.weldforge.service.security;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Getter
@Setter
@ConfigurationProperties(prefix = "app.security.refresh-token")
public class RefreshTokenProperties {

    /**
     * Lifetime of ONE token in days, when neither the client nor the tenant
     * sets one. Rotation mints a successor with a fresh lifetime, so this is
     * the IDLE limit of a session: a family unused for this long dies.
     */
    private int lifetimeDays = 30;

    /**
     * The ABSOLUTE limit of a session, in days from the sign-in that started
     * the family. No successor expires after it, however often the family is
     * used; the person signs in again. Before WF-2 there was none, so a family
     * refreshed at least once per idle period lived for ever.
     */
    private int absoluteLifetimeDays = 30;

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
