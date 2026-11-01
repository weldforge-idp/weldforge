package tech.cwvermaak.weldforge.config.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The platform HMAC key ring (B-JWT-2 / CONF-7.4).
 *
 * <p>The property every test here defends: a retired key verifies and never
 * signs. With one key, rotating the shared secret was an all-or-nothing cutover
 * across WeldForge and three external consumers, because the instant the secret
 * changed every token signed under the old one failed everywhere at once.
 */
@DisplayName("HMAC key ring")
class HmacKeyRingTest {

    /** 64+ bytes, which is the HS512 floor the real validator enforces. */
    private static final String ACTIVE =
            "active-signing-secret-0123456789012345678901234567890123456789012345";
    private static final String RETIRED =
            "retired-verification-secret-98765432109876543210987654321098765432109";
    private static final String OLDER =
            "older-still-verification-secret-5555555555555555555555555555555555555";

    @Nested
    @DisplayName("with no rotation in progress")
    class NoRotation {

        private final HmacKeyRing ring = HmacKeyRing.of(ACTIVE, "");

        @Test
        @DisplayName("holds exactly one key")
        void oneKey() {
            assertThat(ring.verificationKeys()).hasSize(1);
            assertThat(ring.rotationInProgress()).isFalse();
        }

        @Test
        @DisplayName("that key is the signing key")
        void signsWithIt() {
            assertThat(ring.verificationKeys().get(0).getValue()).isEqualTo(ring.signingKey());
            assertThat(ring.verificationKeys().get(0).getKey()).isEqualTo(ring.signingKeyId());
        }

        @Test
        @DisplayName("null and blank previous-secrets are both 'no rotation'")
        void blankIsNoRotation() {
            assertThat(HmacKeyRing.of(ACTIVE, null).rotationInProgress()).isFalse();
            assertThat(HmacKeyRing.of(ACTIVE, "   ").rotationInProgress()).isFalse();
            assertThat(HmacKeyRing.of(ACTIVE, " , , ").rotationInProgress()).isFalse();
        }
    }

    @Nested
    @DisplayName("during a rotation overlap")
    class Rotation {

        private final HmacKeyRing ring = HmacKeyRing.of(ACTIVE, RETIRED + "," + OLDER);

        @Test
        @DisplayName("every key verifies")
        void allVerify() {
            assertThat(ring.verificationKeys()).hasSize(3);
            assertThat(ring.rotationInProgress()).isTrue();
        }

        @Test
        @DisplayName("THE SAFETY PROPERTY: only the active secret signs")
        void onlyActiveSigns() {
            // No configuration of previous-secrets can cause a token to be
            // minted under a retired key. If this ever fails, a rotation could
            // issue tokens that the consumers have already stopped accepting.
            assertThat(ring.signingKey()).isEqualTo(HmacKeyRing.of(ACTIVE, "").signingKey());
            assertThat(ring.signingKeyId()).isEqualTo(HmacKeyRing.keyId(ACTIVE));
        }

        @Test
        @DisplayName("the signing key is tried first, so the common case costs one attempt")
        void signingKeyIsFirst() {
            assertThat(ring.verificationKeys().get(0).getKey()).isEqualTo(ring.signingKeyId());
        }

        @Test
        @DisplayName("retired keys keep their configured order, newest first")
        void retiredOrderPreserved() {
            List<String> kids = ring.verificationKeys().stream().map(java.util.Map.Entry::getKey).toList();
            assertThat(kids).containsExactly(
                    HmacKeyRing.keyId(ACTIVE), HmacKeyRing.keyId(RETIRED), HmacKeyRing.keyId(OLDER));
        }

        @Test
        @DisplayName("each key is reachable by its id")
        void lookupById() {
            assertThat(ring.keyById(HmacKeyRing.keyId(RETIRED))).isPresent();
            assertThat(ring.keyById(HmacKeyRing.keyId(OLDER))).isPresent();
            assertThat(ring.keyById("not-a-kid")).isEmpty();
            assertThat(ring.keyById(null)).isEmpty();
        }

        @Test
        @DisplayName("whitespace around entries is tolerated")
        void whitespaceTolerated() {
            assertThat(HmacKeyRing.of(ACTIVE, "  " + RETIRED + " ,  " + OLDER + "  ")
                    .verificationKeys()).hasSize(3);
        }

        @Test
        @DisplayName("a retired entry equal to the active key is a no-op, not an error")
        void duplicateOfActiveIsIgnored() {
            // Happens when an operator populates the overlap list before
            // swapping the active key. Failing the boot would punish the
            // careful order.
            HmacKeyRing r = HmacKeyRing.of(ACTIVE, ACTIVE);
            assertThat(r.verificationKeys()).hasSize(1);
            assertThat(r.rotationInProgress()).isFalse();
        }
    }

    @Nested
    @DisplayName("key ids")
    class KeyIds {

        @Test
        @DisplayName("are deterministic, so two systems agree with nothing to coordinate")
        void deterministic() {
            assertThat(HmacKeyRing.keyId(ACTIVE)).isEqualTo(HmacKeyRing.keyId(ACTIVE));
        }

        @Test
        @DisplayName("differ between keys")
        void distinct() {
            assertThat(HmacKeyRing.keyId(ACTIVE)).isNotEqualTo(HmacKeyRing.keyId(RETIRED));
        }

        @Test
        @DisplayName("are 16 lower-case hex characters")
        void shape() {
            assertThat(HmacKeyRing.keyId(ACTIVE)).matches("[0-9a-f]{16}");
        }

        @Test
        @DisplayName("do not contain the secret")
        void doNotLeakTheSecret() {
            assertThat(ACTIVE).doesNotContain(HmacKeyRing.keyId(ACTIVE));
            assertThat(HmacKeyRing.keyId(ACTIVE)).doesNotContain(ACTIVE.substring(0, 8));
        }
    }

    @Nested
    @DisplayName("rebuild detection")
    class RebuildDetection {

        @Test
        @DisplayName("knows whether it still reflects the configuration")
        void wasBuiltFrom() {
            HmacKeyRing ring = HmacKeyRing.of(ACTIVE, RETIRED);
            assertThat(ring.wasBuiltFrom(ACTIVE, RETIRED)).isTrue();
            assertThat(ring.wasBuiltFrom(RETIRED, RETIRED)).isFalse();
            assertThat(ring.wasBuiltFrom(ACTIVE, "")).isFalse();
            assertThat(ring.wasBuiltFrom(ACTIVE, null)).isFalse();
        }
    }

    @Nested
    @DisplayName("parse")
    class Parse {

        @Test
        @DisplayName("splits on commas and drops blanks")
        void splits() {
            assertThat(HmacKeyRing.parse("a,b , ,c")).containsExactly("a", "b", "c");
            assertThat(HmacKeyRing.parse("")).isEmpty();
            assertThat(HmacKeyRing.parse(null)).isEmpty();
        }
    }
}
