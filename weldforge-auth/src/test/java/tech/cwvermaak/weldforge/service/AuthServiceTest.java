package tech.cwvermaak.weldforge.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.UserRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * B-AUTH-2: a successful login re-hashes a weaker stored password at the
 * current encoder strength (bcrypt upgrade-on-login).
 */
class AuthServiceTest {

    private UserRepository userRepo;
    private BCryptPasswordEncoder encoder12;
    private AuthService auth;

    @BeforeEach
    void setUp() {
        userRepo = mock(UserRepository.class);
        encoder12 = new BCryptPasswordEncoder(12);
        // Only userRepository + passwordEncoder are used by maybeUpgradePassword.
        auth = new AuthService(userRepo, null, encoder12, null, null, null, null, null,
                null, null, null, null, null, null, null, null);
    }

    @Test
    @DisplayName("a weaker (lower-cost) hash is re-encoded at the current strength and saved")
    void upgradesWeakHash() {
        String weak = new BCryptPasswordEncoder(4).encode("s3cret");
        User u = User.builder().id(1L).password(weak).build();

        auth.maybeUpgradePassword(u, "s3cret");

        verify(userRepo).save(u);
        assertThat(u.getPassword()).isNotEqualTo(weak);
        assertThat(encoder12.matches("s3cret", u.getPassword())).isTrue();
        // Re-hashed at the current strength — no further upgrade needed.
        assertThat(encoder12.upgradeEncoding(u.getPassword())).isFalse();
    }

    @Test
    @DisplayName("a current-strength hash is left untouched (no write)")
    void leavesCurrentHash() {
        String strong = encoder12.encode("s3cret");
        User u = User.builder().id(1L).password(strong).build();

        auth.maybeUpgradePassword(u, "s3cret");

        verify(userRepo, never()).save(any());
        assertThat(u.getPassword()).isEqualTo(strong);
    }

    @Test
    @DisplayName("a null password (e.g. invited/LDAP user) is a no-op")
    void nullPasswordNoop() {
        User u = User.builder().id(1L).password(null).build();

        auth.maybeUpgradePassword(u, "s3cret");

        verify(userRepo, never()).save(any());
    }
}
