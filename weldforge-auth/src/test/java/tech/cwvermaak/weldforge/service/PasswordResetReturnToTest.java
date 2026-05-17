package tech.cwvermaak.weldforge.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;
import tech.cwvermaak.weldforge.config.tenant.TenantContext;
import tech.cwvermaak.weldforge.model.PasswordResetToken;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.PasswordResetTokenRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.audit.AuditService;
import tech.cwvermaak.weldforge.service.mail.MailService;
import tech.cwvermaak.weldforge.service.security.PasswordPolicyService;
import tech.cwvermaak.weldforge.service.security.RefreshTokenService;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Security-focused coverage of the password-reset return-to-caller feature:
 * a return target supplied at forgot-password time is stored against the
 * token only when it is on the auth server's own origin and the tenant has
 * the feature enabled — a reset link must never become an open redirect.
 */
class PasswordResetReturnToTest {

    private static final String BASE = "https://sso.weldforge.org";

    private TenantRepository tenantRepository;
    private UserRepository userRepository;
    private PasswordResetTokenRepository resetTokenRepository;
    private PasswordResetService service;
    private Tenant tenant;

    @BeforeEach
    void setUp() {
        tenantRepository = mock(TenantRepository.class);
        userRepository = mock(UserRepository.class);
        resetTokenRepository = mock(PasswordResetTokenRepository.class);

        service = new PasswordResetService(
                userRepository, tenantRepository, resetTokenRepository,
                mock(PasswordEncoder.class), mock(PasswordPolicyService.class),
                mock(AuditService.class), mock(RefreshTokenService.class), mock(MailService.class));
        ReflectionTestUtils.setField(service, "frontendBaseUrl", BASE);

        tenant = Tenant.builder().id(1L).slug("acme").name("Acme").build();
        TenantContext.set("acme");
        when(tenantRepository.findBySlug("acme")).thenReturn(Optional.of(tenant));

        User user = User.builder().id(7L).tenant(tenant)
                .email("u@acme.test").username("u@acme.test").build();
        when(userRepository.findByTenantIdAndEmailIgnoreCase(eq(1L), anyString()))
                .thenReturn(Optional.of(user));
        when(resetTokenRepository.save(any(PasswordResetToken.class)))
                .thenAnswer(inv -> inv.getArgument(0));
    }

    private static String b64(String url) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(url.getBytes(StandardCharsets.UTF_8));
    }

    private PasswordResetToken savedToken() {
        ArgumentCaptor<PasswordResetToken> cap = ArgumentCaptor.forClass(PasswordResetToken.class);
        verify(resetTokenRepository).save(cap.capture());
        return cap.getValue();
    }

    @Test
    void storesSameOriginReturnTo() {
        String returnTo = b64(BASE + "/t/acme/oauth2/authorize?client_id=spa");
        service.requestReset("u@acme.test", returnTo);
        assertThat(savedToken().getReturnTo()).isEqualTo(returnTo);
    }

    @Test
    void dropsCrossOriginReturnTo() {
        service.requestReset("u@acme.test", b64("https://evil.example.com/phish"));
        assertThat(savedToken().getReturnTo()).isNull();
    }

    @Test
    void dropsMalformedReturnTo() {
        service.requestReset("u@acme.test", "%%not-valid-base64%%");
        assertThat(savedToken().getReturnTo()).isNull();
    }

    @Test
    void dropsReturnToWhenTenantFlagDisabled() {
        tenant.setReturnToCallerEnabled(false);
        service.requestReset("u@acme.test", b64(BASE + "/t/acme/oauth2/authorize"));
        assertThat(savedToken().getReturnTo()).isNull();
    }

    @Test
    void noReturnToWhenNoneSupplied() {
        service.requestReset("u@acme.test", null);
        assertThat(savedToken().getReturnTo()).isNull();
    }
}
