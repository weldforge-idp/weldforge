package tech.cwvermaak.weldforge.config.tenant;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Cookie-scoping rules for the hosted login flow. The login form runs on the
 * tenant subdomain while the OIDC authorize step runs on the apex, so the
 * session cookie has to survive that hop — in both directions it can fail
 * silently, and the only visible symptom is the login form re-appearing.
 */
class PublicHostPropertiesCookieTest {

    private PublicHostProperties props(String baseDomain, String scheme) {
        PublicHostProperties p = new PublicHostProperties();
        p.setBaseDomain(baseDomain);
        p.setScheme(scheme);
        return p;
    }

    @Test
    @DisplayName("production: cookies are Secure and scoped to the parent domain")
    void productionScopesToParentAndStaysSecure() {
        PublicHostProperties p = props("sso.weldforge.org", "https");
        assertThat(p.isSecureCookies()).isTrue();
        assertThat(p.cookieDomain()).isEqualTo("sso.weldforge.org");
    }

    @Test
    @DisplayName("an http deployment drops Secure, which browsers would otherwise discard")
    void httpDropsSecure() {
        assertThat(props("lvh.me:8076", "http").isSecureCookies()).isFalse();
    }

    @Test
    @DisplayName("a missing or odd scheme errs secure")
    void unknownSchemeErrsSecure() {
        assertThat(props("sso.weldforge.org", null).isSecureCookies()).isTrue();
        assertThat(props("sso.weldforge.org", "HTTPS").isSecureCookies()).isTrue();
        assertThat(props("sso.weldforge.org", "").isSecureCookies()).isTrue();
    }

    @Test
    @DisplayName("the cookie domain drops any dev port — Domain must never carry one")
    void cookieDomainStripsPort() {
        assertThat(props("lvh.me:8076", "http").cookieDomain()).isEqualTo("lvh.me");
    }

    @Test
    @DisplayName("a single-label base stays host-only, so apex and subdomain cannot share")
    void singleLabelBaseIsHostOnly() {
        assertThat(props("localhost:8076", "http").cookieDomain()).isNull();
    }

    @Test
    @DisplayName("host and port halves of the base domain are exposed separately")
    void splitsBaseDomain() {
        PublicHostProperties ported = props("lvh.me:8076", "http");
        assertThat(ported.getBaseDomainHost()).isEqualTo("lvh.me");
        assertThat(ported.getBaseDomainPort()).isEqualTo(8076);

        PublicHostProperties plain = props("sso.weldforge.org", "https");
        assertThat(plain.getBaseDomainHost()).isEqualTo("sso.weldforge.org");
        assertThat(plain.getBaseDomainPort()).isEqualTo(-1);
    }

    @Test
    @DisplayName("a tenant subdomain still resolves when the base domain carries a port")
    void slugFromHostIgnoresPorts() {
        PublicHostProperties p = props("lvh.me:8076", "http");
        assertThat(p.slugFromHost("wellspring.lvh.me:8076")).isEqualTo("wellspring");
        assertThat(p.slugFromHost("wellspring.lvh.me")).isEqualTo("wellspring");
        assertThat(p.slugFromHost("lvh.me:8076")).isNull();
    }
}
