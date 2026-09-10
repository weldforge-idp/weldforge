package tech.cwvermaak.weldforge.service.security;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The k-anonymity screen (CONF-7.1). The property that matters most is the one
 * the acceptance criterion names: the password is never transmitted in full.
 */
class PwnedPasswordsScreenTest {

    // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    private static final String PASSWORD = "password";
    private static final String PREFIX = "5BAA6";
    private static final String SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

    private final SimpleMeterRegistry meters = new SimpleMeterRegistry();

    private double count(String outcome) {
        return meters.counter("sso.password.breach_check", "outcome", outcome).count();
    }

    @Test
    @DisplayName("Only the five-character hash prefix is sent -- never the password or its full hash")
    void sends_only_prefix() {
        List<String> sent = new ArrayList<>();
        PwnedPasswordsScreen screen = new PwnedPasswordsScreen("https://corpus.test/range/", prefix -> {
            sent.add(prefix);
            return "";
        }, meters);

        screen.check(PASSWORD);

        assertThat(sent).containsExactly(PREFIX);
        assertThat(sent.get(0)).doesNotContain(PASSWORD).hasSize(5);
    }

    @Test
    @DisplayName("A suffix in the range with a non-zero count is a breach")
    void finds_breach() {
        PwnedPasswordsScreen screen = new PwnedPasswordsScreen("https://corpus.test/range/",
                prefix -> "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n" + SUFFIX + ":9545824\r\n", meters);

        assertThat(screen.check(PASSWORD)).isEqualTo(BreachedPasswordScreen.Result.BREACHED);
        assertThat(count("breached")).isEqualTo(1);
    }

    @Test
    @DisplayName("Padding entries (count 0) are decoys, not breaches")
    void ignores_padding() {
        PwnedPasswordsScreen screen = new PwnedPasswordsScreen("https://corpus.test/range/",
                prefix -> SUFFIX + ":0\r\n", meters);

        assertThat(screen.check(PASSWORD)).isEqualTo(BreachedPasswordScreen.Result.CLEAN);
    }

    @Test
    @DisplayName("A range without the suffix is clean")
    void clean_when_absent() {
        PwnedPasswordsScreen screen = new PwnedPasswordsScreen("https://corpus.test/range/",
                prefix -> "0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n", meters);

        assertThat(screen.check(PASSWORD)).isEqualTo(BreachedPasswordScreen.Result.CLEAN);
        assertThat(count("clean")).isEqualTo(1);
    }

    @Test
    @DisplayName("An outage fails open and is counted, so a silent stop is visible")
    void fails_open() {
        PwnedPasswordsScreen screen = new PwnedPasswordsScreen("https://corpus.test/range/", prefix -> {
            throw new IllegalStateException("connect timed out");
        }, meters);

        assertThat(screen.check(PASSWORD)).isEqualTo(BreachedPasswordScreen.Result.UNAVAILABLE);
        assertThat(count("unavailable")).isEqualTo(1);
    }

    @Test
    @DisplayName("A range URL pointing inside the network is refused by the egress guard, and fails open")
    void egress_guard_applies() {
        PwnedPasswordsScreen screen = new PwnedPasswordsScreen(
                "http://169.254.169.254/range/", java.time.Duration.ofMillis(200), meters);

        assertThat(screen.check(PASSWORD)).isEqualTo(BreachedPasswordScreen.Result.UNAVAILABLE);
    }
}
