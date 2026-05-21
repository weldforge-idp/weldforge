package tech.cwvermaak.weldforge.service;

import jakarta.persistence.EntityNotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.test.util.ReflectionTestUtils;
import tech.cwvermaak.weldforge.config.tenant.PublicHostProperties;
import tech.cwvermaak.weldforge.config.tenant.TenantAccessor;
import tech.cwvermaak.weldforge.config.tenant.TenantContext;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.TenantVerificationToken;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.TenantVerificationTokenRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.audit.AuditEventTypes;
import tech.cwvermaak.weldforge.service.audit.AuditService;
import tech.cwvermaak.weldforge.service.mail.MailService;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Email-based identity-proofing — see {@code docs/auth-url-spec.md}
 * §"Tenant identity-proofing".
 */
class TenantVerificationServiceTest {

    private final TenantAccessor accessor = mock(TenantAccessor.class);
    private final TenantRepository tenantRepository = mock(TenantRepository.class);
    private final UserRepository userRepository = mock(UserRepository.class);
    private final TenantVerificationTokenRepository tokenRepository =
            mock(TenantVerificationTokenRepository.class);
    private final AuditService auditService = mock(AuditService.class);
    private final MailService mailService = mock(MailService.class);
    private final PublicHostProperties publicHost = publicHost();

    private final TenantVerificationService service = new TenantVerificationService(
            accessor, tenantRepository, userRepository, tokenRepository,
            auditService, mailService, publicHost);

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(service, "verifyContactPath",
                "/api/auth/tenants/verify-contact-page");
        TenantContext.clear();
    }

    @Test
    @DisplayName("requestVerification mints a token, emails it, audits, and invalidates pending")
    void request_happy_path() {
        Tenant t = Tenant.builder().id(7L).slug("acme").name("Acme")
                .contactEmail("ops@acme.com").build();
        when(tenantRepository.findById(7L)).thenReturn(Optional.of(t));
        when(tokenRepository.invalidatePendingForTenant(eq(7L), any())).thenReturn(2);

        service.requestVerification(7L);

        // Token row was saved with hashed token and snapshot contactEmail.
        ArgumentCaptor<TenantVerificationToken> rowCap =
                ArgumentCaptor.forClass(TenantVerificationToken.class);
        verify(tokenRepository).save(rowCap.capture());
        TenantVerificationToken row = rowCap.getValue();
        assertThat(row.getContactEmail()).isEqualTo("ops@acme.com");
        assertThat(row.getTokenHash()).matches("[a-f0-9]{64}");
        assertThat(row.getExpiresAt()).isAfter(LocalDateTime.now().plusHours(47));

        // Email was sent to the contact_email.
        verify(mailService).send(eq("ops@acme.com"), anyString(), anyString());

        // Pending tokens were invalidated before the new one was issued.
        verify(tokenRepository).invalidatePendingForTenant(eq(7L), any());

        // Audit emitted.
        verify(auditService).recordAdmin(
                eq(AuditEventTypes.TENANT_VERIFICATION_REQUESTED), any(),
                eq(AuditEventTypes.TARGET_TENANT), eq("7"), any());
    }

    @Test
    @DisplayName("requestVerification rejects when the tenant has no contact_email")
    void request_no_contact_email_throws() {
        Tenant t = Tenant.builder().id(7L).slug("acme").name("Acme").build();
        when(tenantRepository.findById(7L)).thenReturn(Optional.of(t));

        assertThatThrownBy(() -> service.requestVerification(7L))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("contact_email");

        verify(mailService, never()).send(anyString(), anyString(), anyString());
        verify(tokenRepository, never()).save(any());
    }

    @Test
    @DisplayName("requestVerification refuses when the caller is not at least TENANT_ADMIN")
    void request_rejects_non_admin() {
        Tenant t = Tenant.builder().id(7L).slug("acme").name("Acme")
                .contactEmail("ops@acme.com").build();
        when(tenantRepository.findById(7L)).thenReturn(Optional.of(t));
        doThrow(new AccessDeniedException("tenant admin required"))
                .when(accessor).requireTenantAdmin();

        assertThatThrownBy(() -> service.requestVerification(7L))
                .isInstanceOf(AccessDeniedException.class);
    }

    @Test
    @DisplayName("requestVerification on unknown tenant throws 404")
    void request_unknown_tenant() {
        when(tenantRepository.findById(999L)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.requestVerification(999L))
                .isInstanceOf(EntityNotFoundException.class);
    }

    @Test
    @DisplayName("consumeToken flips verified_at, marks the token used, and audits")
    void consume_happy_path() {
        Tenant t = Tenant.builder().id(7L).slug("acme").name("Acme")
                .contactEmail("ops@acme.com").build();
        String raw = "fixed-token-for-tests-aaaaaaaaaaaaaaaaaaaaaa";
        TenantVerificationToken row = TenantVerificationToken.builder()
                .id(1L)
                .tenant(t)
                .tokenHash(TenantVerificationService.sha256Hex(raw))
                .contactEmail("ops@acme.com")
                .expiresAt(LocalDateTime.now().plusHours(24))
                .createdAt(LocalDateTime.now().minusHours(24))
                .build();
        when(tokenRepository.findByTokenHash(row.getTokenHash())).thenReturn(Optional.of(row));

        TenantVerificationService.VerificationResult result = service.consumeToken(raw);

        assertThat(t.getVerifiedAt()).isNotNull();
        assertThat(row.getUsedAt()).isNotNull();
        assertThat(result.slug()).isEqualTo("acme");
        verify(tenantRepository).save(t);
        verify(tokenRepository).save(row);
        verify(auditService).recordAdmin(
                eq(AuditEventTypes.TENANT_VERIFIED), eq(null),
                eq(AuditEventTypes.TARGET_TENANT), eq("7"), any());
    }

    @Test
    @DisplayName("consumeToken rejects an unknown token with the generic 'invalid' message")
    void consume_unknown_token() {
        when(tokenRepository.findByTokenHash(anyString())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.consumeToken("totally-bogus-token"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid or expired");
    }

    @Test
    @DisplayName("consumeToken rejects an expired token with the same generic message")
    void consume_expired_token() {
        Tenant t = Tenant.builder().id(7L).slug("acme").name("Acme").build();
        String raw = "fixed-token-expired";
        TenantVerificationToken row = TenantVerificationToken.builder()
                .tenant(t)
                .tokenHash(TenantVerificationService.sha256Hex(raw))
                .contactEmail("ops@acme.com")
                .expiresAt(LocalDateTime.now().minusHours(1))  // already expired
                .build();
        when(tokenRepository.findByTokenHash(row.getTokenHash())).thenReturn(Optional.of(row));

        assertThatThrownBy(() -> service.consumeToken(raw))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid or expired");
        assertThat(t.getVerifiedAt())
                .as("expired token must not flip the verified bit")
                .isNull();
    }

    @Test
    @DisplayName("consumeToken rejects a token that was already used (single-use)")
    void consume_used_token() {
        Tenant t = Tenant.builder().id(7L).slug("acme").name("Acme").build();
        String raw = "fixed-token-used";
        TenantVerificationToken row = TenantVerificationToken.builder()
                .tenant(t)
                .tokenHash(TenantVerificationService.sha256Hex(raw))
                .contactEmail("ops@acme.com")
                .expiresAt(LocalDateTime.now().plusHours(24))
                .usedAt(LocalDateTime.now().minusMinutes(1))    // already consumed
                .build();
        when(tokenRepository.findByTokenHash(row.getTokenHash())).thenReturn(Optional.of(row));

        assertThatThrownBy(() -> service.consumeToken(raw))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid or expired");
    }

    @Test
    @DisplayName("consumeToken on a previously-verified tenant records the re-verification flag")
    void consume_re_verification_flag() {
        Tenant t = Tenant.builder().id(7L).slug("acme").name("Acme")
                .verifiedAt(LocalDateTime.now().minusDays(30)).build();
        String raw = "fixed-token-reverify";
        TenantVerificationToken row = TenantVerificationToken.builder()
                .tenant(t)
                .tokenHash(TenantVerificationService.sha256Hex(raw))
                .contactEmail("ops@acme.com")
                .expiresAt(LocalDateTime.now().plusHours(24))
                .build();
        when(tokenRepository.findByTokenHash(row.getTokenHash())).thenReturn(Optional.of(row));

        service.consumeToken(raw);

        ArgumentCaptor<java.util.Map<String, Object>> metaCap =
                ArgumentCaptor.forClass(java.util.Map.class);
        verify(auditService).recordAdmin(
                eq(AuditEventTypes.TENANT_VERIFIED), eq(null),
                anyString(), anyString(), metaCap.capture());
        assertThat(metaCap.getValue()).containsEntry("re_verification", true);
        assertThat(metaCap.getValue()).containsEntry("channel", "email_challenge");
    }

    @Test
    @DisplayName("consumeToken rejects a blank or null token without a DB lookup")
    void consume_blank_token() {
        assertThatThrownBy(() -> service.consumeToken(""))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.consumeToken(null))
                .isInstanceOf(IllegalArgumentException.class);
        verify(tokenRepository, never()).findByTokenHash(anyString());
    }

    private static PublicHostProperties publicHost() {
        PublicHostProperties p = new PublicHostProperties();
        p.setBaseDomain("sso.weldforge.org");
        p.setScheme("https");
        return p;
    }
}
