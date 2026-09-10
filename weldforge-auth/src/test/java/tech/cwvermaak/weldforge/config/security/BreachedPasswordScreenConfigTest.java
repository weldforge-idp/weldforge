package tech.cwvermaak.weldforge.config.security;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.ClassPathResource;
import tech.cwvermaak.weldforge.service.security.BreachedPasswordScreen;
import tech.cwvermaak.weldforge.service.security.PasswordPolicyProperties;
import tech.cwvermaak.weldforge.service.security.PwnedPasswordsScreen;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * CONF-7.1 wiring: the screen bean follows the flag, and the shipped
 * {@code application.yml} binds to the 800-63B defaults. The binding test reads
 * the real file, so a typo in a key or an env-var default is caught here rather
 * than by a user whose {@code Password1!} is suddenly accepted.
 */
class BreachedPasswordScreenConfigTest {

    private final BreachedPasswordScreenConfig config = new BreachedPasswordScreenConfig();

    @Test
    @DisplayName("Enabled (the default) wires the k-anonymity screen")
    void enabled_wires_pwned_passwords() {
        BreachedPasswordScreen screen = config.breachedPasswordScreen(
                new PasswordPolicyProperties(), new SimpleMeterRegistry());

        assertThat(screen).isInstanceOf(PwnedPasswordsScreen.class);
    }

    @Test
    @DisplayName("Disabled wires the no-op screen, which accepts everything")
    void disabled_wires_noop() {
        PasswordPolicyProperties props = new PasswordPolicyProperties();
        props.getBreachCheck().setEnabled(false);

        BreachedPasswordScreen screen = config.breachedPasswordScreen(props, new SimpleMeterRegistry());

        assertThat(screen).isSameAs(BreachedPasswordScreen.DISABLED);
        assertThat(screen.check("password")).isEqualTo(BreachedPasswordScreen.Result.CLEAN);
    }

    @Test
    @DisplayName("application.yml binds to the 800-63B defaults when no env var overrides them")
    void shipped_yaml_binds_to_nist_defaults() throws Exception {
        StandardEnvironment env = new StandardEnvironment();
        // Isolate from the machine running the tests: only the shipped file,
        // with its ${VAR:default} placeholders resolved to their defaults.
        env.getPropertySources().remove(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME);
        env.getPropertySources().remove(StandardEnvironment.SYSTEM_PROPERTIES_PROPERTY_SOURCE_NAME);
        new YamlPropertySourceLoader().load("application", new ClassPathResource("application.yml"))
                .forEach(env.getPropertySources()::addLast);
        ConfigurationPropertySources.attach(env);

        PasswordPolicyProperties bound = Binder.get(env)
                .bind("app.security.password", PasswordPolicyProperties.class)
                .orElseThrow(() -> new AssertionError("app.security.password did not bind"));

        assertThat(bound.getMinLength()).isEqualTo(12);
        assertThat(bound.getMaxLength()).isEqualTo(72);
        assertThat(bound.isRequireUppercase()).isFalse();
        assertThat(bound.isRequireLowercase()).isFalse();
        assertThat(bound.isRequireDigit()).isFalse();
        assertThat(bound.isRequireSymbol()).isFalse();
        assertThat(bound.getBreachCheck().isEnabled()).isTrue();
        assertThat(bound.getBreachCheck().getRangeUrl()).isEqualTo(PwnedPasswordsScreen.DEFAULT_RANGE_URL);
        assertThat(bound.getBreachCheck().getTimeout()).isEqualTo(Duration.ofSeconds(2));
    }
}
