package tech.cwvermaak.intellisso.service.mfa;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import tech.cwvermaak.intellisso.model.BackupCode;
import tech.cwvermaak.intellisso.model.Tenant;
import tech.cwvermaak.intellisso.model.User;
import tech.cwvermaak.intellisso.repository.BackupCodeRepository;
import tech.cwvermaak.intellisso.service.audit.AuditEventTypes;
import tech.cwvermaak.intellisso.service.audit.AuditService;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class BackupCodeServiceTest {

    private BackupCodeRepository repo;
    private AuditService auditService;
    private PasswordEncoder encoder;
    private BackupCodeService service;
    private User user;

    @BeforeEach
    void setUp() {
        repo = mock(BackupCodeRepository.class);
        auditService = mock(AuditService.class);
        encoder = new BCryptPasswordEncoder(4); // low cost for fast tests
        service = new BackupCodeService(repo, encoder, auditService);

        Tenant t = Tenant.builder().id(1L).slug("acme").name("Acme").build();
        user = User.builder().id(42L).tenant(t).email("alice@acme.test").build();
    }

    @Test
    @DisplayName("regenerate wipes the previous set, mints 10 display codes, and audits")
    void regenerate_producesTenFreshCodesAndAudits() {
        List<String> codes = service.regenerate(user);

        assertThat(codes).hasSize(10);
        // Human-friendly display format: 5-5 groupings.
        assertThat(codes).allMatch(c -> c.matches("[A-Z2-9]{5}-[A-Z2-9]{5}"));

        verify(repo).deleteAllByUserId(42L);
        ArgumentCaptor<List<BackupCode>> captor = ArgumentCaptor.forClass(List.class);
        verify(repo).saveAll(captor.capture());
        assertThat(captor.getValue()).hasSize(10);
        // Codes are stored hashed — never in plaintext.
        captor.getValue().forEach(row -> assertThat(row.getCodeHash()).isNotEqualTo(codes.get(0)));

        verify(auditService).recordUserAction(eq(AuditEventTypes.MFA_BACKUP_CODES_REGENERATED),
                eq(user), any(), any(), any());
    }

    @Test
    @DisplayName("regenerate + consume round-trip: the plaintext shown to the user redeems cleanly")
    void regenerate_thenConsume_roundTrip() {
        // End-to-end contract: whatever regenerate shows the user must match
        // whatever consume will later accept — regardless of dashes.
        ArgumentCaptor<List<BackupCode>> captor = ArgumentCaptor.forClass(List.class);

        List<String> plaintext = service.regenerate(user);
        verify(repo).saveAll(captor.capture());
        List<BackupCode> saved = captor.getValue();

        when(repo.findByUserIdAndUsedAtIsNull(42L)).thenReturn(new ArrayList<>(saved));

        assertThat(service.consume(user, plaintext.get(0))).isTrue();
    }

    @Test
    @DisplayName("consume accepts the code whether the user types the dash or not")
    void consume_normalisesDashAndCase() {
        // Historical bug: regenerate stored the dash inside the hash, but
        // consume stripped it before matching, so codes never validated.
        // This guards against that regression.
        List<String> plaintext = service.regenerate(user);
        ArgumentCaptor<List<BackupCode>> captor = ArgumentCaptor.forClass(List.class);
        verify(repo).saveAll(captor.capture());
        when(repo.findByUserIdAndUsedAtIsNull(42L)).thenReturn(new ArrayList<>(captor.getValue()));

        // User typing: dash omitted, case flipped, leading space.
        String messy = " " + plaintext.get(0).replace("-", "").toLowerCase();
        assertThat(service.consume(user, messy)).isTrue();
    }

    @Test
    @DisplayName("consume rejects an invalid code and does not persist anything")
    void consume_rejectsInvalidCode() {
        when(repo.findByUserIdAndUsedAtIsNull(42L)).thenReturn(Collections.emptyList());

        boolean consumed = service.consume(user, "WRONG-CODE9");

        assertThat(consumed).isFalse();
        verify(repo, never()).save(any());
    }

    @Test
    @DisplayName("consume rejects null / blank input without NPE")
    void consume_rejectsBlankInput() {
        assertThat(service.consume(user, null)).isFalse();
        assertThat(service.consume(user, "")).isFalse();
        verifyNoInteractions(repo);
    }
}
