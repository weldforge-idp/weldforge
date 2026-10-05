package tech.cwvermaak.weldforge.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static tech.cwvermaak.weldforge.service.EmailDomainPolicy.*;

/**
 * Who may sign in to a tenant.
 *
 * <p>A tenant federated to Google Workspace accepts any Google account unless
 * something says otherwise — the sign-in URL was the only thing between a
 * stranger's personal address and the tenant, and a URL is not an access
 * control.
 *
 * <p>The suffix rule is the part worth being exact about. {@code example.com}
 * must admit {@code eu.example.com} and must NOT admit
 * {@code notexample.com}: the dot is what makes the match a boundary rather
 * than a string, and leaving it out is how an allow-list admits an
 * attacker-registered lookalike.
 */
@DisplayName("Tenant email-domain policy")
class EmailDomainPolicyTest {

    @Nested
    @DisplayName("parsing what an administrator typed")
    class Parsing {

        @Test
        @DisplayName("absent means unrestricted")
        void empty() {
            assertThat(parse(null)).isEmpty();
            assertThat(parse("")).isEmpty();
            assertThat(parse("   ")).isEmpty();
        }

        @Test
        @DisplayName("space-separated, lower-cased, de-duplicated")
        void list() {
            assertThat(parse("Example.com  OTHER.org example.com"))
                    .containsExactly("example.com", "other.org");
        }

        @Test
        @DisplayName("tolerates @example.com and .example.com")
        void tolerantShapes() {
            assertThat(parse("@example.com")).containsExactly("example.com");
            assertThat(parse(".example.com")).containsExactly("example.com");
        }
    }

    @Nested
    @DisplayName("domainOf")
    class DomainOf {

        @Test
        @DisplayName("takes the part after the LAST @")
        void lastAt() {
            assertThat(domainOf("a@b@example.com")).isEqualTo("example.com");
            assertThat(domainOf("Alice@Example.COM")).isEqualTo("example.com");
        }

        @Test
        @DisplayName("null for anything without a usable domain")
        void unusable() {
            assertThat(domainOf(null)).isNull();
            assertThat(domainOf("no-at-sign")).isNull();
            assertThat(domainOf("trailing@")).isNull();
        }
    }

    @Nested
    @DisplayName("permits")
    class Permits {

        private static final List<String> ALLOWED = List.of("example.com");

        @Test
        @DisplayName("an empty list restricts nothing — every tenant today")
        void unrestricted() {
            assertThat(permits(List.of(), "anyone@anywhere.test", null)).isTrue();
            assertThat(permits(null, "anyone@anywhere.test", null)).isTrue();
        }

        @Test
        @DisplayName("an exact domain is admitted, case-insensitively")
        void exact() {
            assertThat(permits(ALLOWED, "alice@example.com", null)).isTrue();
            assertThat(permits(ALLOWED, "Alice@EXAMPLE.com", null)).isTrue();
        }

        @Test
        @DisplayName("a subdomain is admitted")
        void subdomain() {
            assertThat(permits(ALLOWED, "alice@eu.example.com", null)).isTrue();
        }

        @Test
        @DisplayName("a lookalike is NOT admitted — the dot is the boundary")
        void lookalike() {
            assertThat(permits(ALLOWED, "mallory@notexample.com", null)).isFalse();
            assertThat(permits(ALLOWED, "mallory@example.com.evil.test", null)).isFalse();
        }

        @Test
        @DisplayName("an outside domain is refused")
        void outside() {
            assertThat(permits(ALLOWED, "stranger@gmail.com", null)).isFalse();
        }

        @Test
        @DisplayName("an address with no domain is refused when a list is set")
        void malformed() {
            assertThat(permits(ALLOWED, "no-at-sign", null)).isFalse();
            assertThat(permits(ALLOWED, null, null)).isFalse();
        }

        @Test
        @DisplayName("the hosted domain must ALSO be allowed")
        void hostedDomainMustAlsoPass() {
            // A Workspace account can carry an address in one domain while the
            // account belongs to another organisation. The organisation is the
            // thing being admitted, so both have to pass.
            assertThat(permits(ALLOWED, "alice@example.com", "example.com")).isTrue();
            assertThat(permits(ALLOWED, "alice@example.com", "someone-else.test")).isFalse();
        }

        @Test
        @DisplayName("no hosted domain is not a failure — most providers send none")
        void noHostedDomain() {
            assertThat(permits(ALLOWED, "alice@example.com", null)).isTrue();
            assertThat(permits(ALLOWED, "alice@example.com", "")).isTrue();
        }

        @Test
        @DisplayName("several allowed domains all work")
        void several() {
            List<String> many = List.of("example.com", "other.org");
            assertThat(permits(many, "a@example.com", null)).isTrue();
            assertThat(permits(many, "b@other.org", null)).isTrue();
            assertThat(permits(many, "c@third.net", null)).isFalse();
        }
    }
}
