package tech.cwvermaak.weldforge.service.oidc;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import tech.cwvermaak.weldforge.model.OidcClient;
import tech.cwvermaak.weldforge.model.Tenant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The resolution rule on its own: client, then tenant, then the deployment
 * default, with the tenant's number as a ceiling the client cannot pass.
 */
@DisplayName("AccessTokenLifetime")
class AccessTokenLifetimeTest {

    private static final long INSTANCE_DEFAULT = 3600L;

    private final AccessTokenLifetime lifetime = new AccessTokenLifetime(INSTANCE_DEFAULT);

    private static Tenant tenant(Long accessTtlMs) {
        return Tenant.builder().id(1L).slug("acme").name("Acme").accessTtlMs(accessTtlMs).build();
    }

    private static OidcClient client(Integer accessTokenTtlSeconds) {
        return OidcClient.builder().id(10L).clientId("acme-app")
                .accessTokenTtlSeconds(accessTokenTtlSeconds).build();
    }

    @Nested
    @DisplayName("most specific wins")
    class Precedence {

        @Test
        @DisplayName("a tenant with no override gets the deployment default")
        void tenantUnset() {
            assertThat(lifetime.forTenant(tenant(null))).isEqualTo(INSTANCE_DEFAULT);
        }

        @Test
        @DisplayName("a tenant override beats the deployment default")
        void tenantOverride() {
            assertThat(lifetime.forTenant(tenant(600_000L))).isEqualTo(600L);
        }

        @Test
        @DisplayName("a client with no value of its own inherits the tenant's")
        void clientUnset() {
            assertThat(lifetime.forClient(tenant(600_000L), client(null))).isEqualTo(600L);
        }

        @Test
        @DisplayName("a client asking for less than the tenant gets what it asked for")
        void clientShorter() {
            assertThat(lifetime.forClient(tenant(600_000L), client(120))).isEqualTo(120L);
        }

        @Test
        @DisplayName("no client in scope resolves to the tenant's lifetime")
        void noClient() {
            assertThat(lifetime.forClient(tenant(600_000L), null)).isEqualTo(600L);
        }
    }

    @Nested
    @DisplayName("a client may shorten, never lengthen")
    class Ceiling {

        @Test
        @DisplayName("a client asking for more than the tenant is capped at the tenant")
        void clientLonger() {
            assertThat(lifetime.forClient(tenant(600_000L), client(86_400))).isEqualTo(600L);
        }

        @Test
        @DisplayName("with no tenant override the deployment default is the ceiling")
        void cappedAtInstanceDefault() {
            assertThat(lifetime.forClient(tenant(null), client(86_400))).isEqualTo(INSTANCE_DEFAULT);
        }

        @Test
        @DisplayName("exactly at the ceiling is allowed")
        void atTheCeiling() {
            assertThat(lifetime.forClient(tenant(600_000L), client(600))).isEqualTo(600L);
        }

        /**
         * The reason the cap is applied at issuance and not only at
         * registration. Nothing re-validates a stored client value when the
         * tenant's own setting changes, so a value that was legal when it was
         * written can be above the policy a moment later.
         */
        @Test
        @DisplayName("a tenant that lowers its own TTL immediately caps clients registered under the old one")
        void tenantLowersAfterRegistration() {
            OidcClient registeredUnderTheOldPolicy = client(1800);

            assertThat(lifetime.forClient(tenant(3_600_000L), registeredUnderTheOldPolicy))
                    .isEqualTo(1800L);
            assertThat(lifetime.forClient(tenant(900_000L), registeredUnderTheOldPolicy))
                    .isEqualTo(900L);
        }
    }

    @Nested
    @DisplayName("zero is not the sentinel for unset, but it cannot produce a zero-second token either")
    class Degenerate {

        @Test
        @DisplayName("a zero or negative tenant override falls through to the deployment default")
        void tenantZeroOrNegative() {
            assertThat(lifetime.forTenant(tenant(0L))).isEqualTo(INSTANCE_DEFAULT);
            assertThat(lifetime.forTenant(tenant(-1L))).isEqualTo(INSTANCE_DEFAULT);
        }

        @Test
        @DisplayName("a zero or negative client value falls through to the tenant's")
        void clientZeroOrNegative() {
            assertThat(lifetime.forClient(tenant(600_000L), client(0))).isEqualTo(600L);
            assertThat(lifetime.forClient(tenant(600_000L), client(-5))).isEqualTo(600L);
        }

        @Test
        @DisplayName("a null tenant resolves to the deployment default rather than throwing")
        void nullTenant() {
            assertThat(lifetime.forTenant(null)).isEqualTo(INSTANCE_DEFAULT);
            assertThat(lifetime.forClient(null, client(120))).isEqualTo(120L);
        }
    }
}
