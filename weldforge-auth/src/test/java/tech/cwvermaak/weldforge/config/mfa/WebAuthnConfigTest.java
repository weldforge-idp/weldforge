package tech.cwvermaak.weldforge.config.mfa;

import com.yubico.webauthn.RelyingParty;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;
import tech.cwvermaak.weldforge.service.mfa.WebAuthnCredentialRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * CONF-3.0 — WebAuthn must work on per-tenant subdomains.
 *
 * <p>Yubico's {@code origins} list is an EXACT-match allow-list with no
 * wildcard syntax, and tenant hosts are minted at runtime as
 * {@code https://{slug}.<base>}, so they can never be enumerated in
 * configuration. Without {@code allowOriginSubdomain}, registration succeeds on
 * the apex and fails on every tenant host with an origin mismatch — which is
 * exactly what production does today, because it configures a single exact
 * origin (see the production overlay's {@code APP_MFA_WEBAUTHN_ORIGINS}).
 *
 * <p>These assertions are on the built {@link RelyingParty}, not on the config
 * class's fields, so they fail if the builder call is dropped in a refactor.
 */
class WebAuthnConfigTest {

    private RelyingParty build(String rpId, String originsCsv) {
        WebAuthnConfig config = new WebAuthnConfig();
        ReflectionTestUtils.setField(config, "rpId", rpId);
        ReflectionTestUtils.setField(config, "rpName", "WeldForge");
        ReflectionTestUtils.setField(config, "originsCsv", originsCsv);
        return config.webAuthnRelyingParty(mock(WebAuthnCredentialRepository.class));
    }

    @Test
    @DisplayName("Subdomain origins are accepted, so tenant hosts can complete a ceremony")
    void allows_tenant_subdomains() {
        RelyingParty rp = build("sso.weldforge.org", "https://sso.weldforge.org");

        assertThat(rp.isAllowOriginSubdomain())
                .as("a tenant host like https://leap.sso.weldforge.org must be accepted; "
                    + "the origins list cannot enumerate hosts created at runtime")
                .isTrue();
    }

    @Test
    @DisplayName("The configured origin set is still the boundary — it is widened, not abandoned")
    void origins_remain_the_boundary() {
        RelyingParty rp = build("sso.weldforge.org", "https://sso.weldforge.org");

        // allowOriginSubdomain widens acceptance to subdomains OF THESE ORIGINS
        // only. An unrelated host is not a subdomain of any of them, so it stays
        // rejected — the flag is not a blanket "any origin".
        assertThat(rp.getOrigins()).containsExactly("https://sso.weldforge.org");
    }

    @Test
    @DisplayName("The RP id is the registrable base, so credentials span tenant subdomains")
    void rp_id_is_the_registrable_base() {
        RelyingParty rp = build("sso.weldforge.org", "https://sso.weldforge.org");

        // rp-id already scopes credentials across exactly the set of hosts that
        // allowOriginSubdomain admits. The two settings have to agree, or a
        // credential is usable on a host whose origin is refused.
        assertThat(rp.getIdentity().getId()).isEqualTo("sso.weldforge.org");
    }

    @Test
    @DisplayName("A multi-origin deployment keeps every configured origin")
    void multiple_origins_are_parsed() {
        RelyingParty rp = build("localhost", "http://localhost:4200, http://localhost:8076");

        assertThat(rp.getOrigins())
                .containsExactly("http://localhost:4200", "http://localhost:8076");
        assertThat(rp.isAllowOriginPort())
                .as("dev runs the SPA and the API on different ports")
                .isTrue();
    }
}
