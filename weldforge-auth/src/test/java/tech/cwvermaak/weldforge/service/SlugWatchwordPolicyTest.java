package tech.cwvermaak.weldforge.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.service.audit.AuditEventTypes;
import tech.cwvermaak.weldforge.service.audit.AuditService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * Identity-proofing V2c — a brand-sensitive slug is flagged for super-admin
 * review at creation; a clean slug is untouched.
 */
class SlugWatchwordPolicyTest {

    private final TenantRepository tenantRepository = mock(TenantRepository.class);
    private final AuditService auditService = mock(AuditService.class);
    private final SlugWatchwordPolicy policy =
            new SlugWatchwordPolicy("bank,pay,secure,official", tenantRepository, auditService);

    @Test
    @DisplayName("matched() finds a watchword as a substring, case-insensitively, first configured wins")
    void matched_substring() {
        // Configured order is bank,pay,secure,official — "bank" is tried first.
        assertThat(policy.matched("securebank")).isEqualTo("bank");
        assertThat(policy.matched("FirstPay")).isEqualTo("pay");
        assertThat(policy.matched("acme")).isNull();
        assertThat(policy.matched(null)).isNull();
    }

    @Test
    @DisplayName("flagIfWatchword flags a brand-sensitive slug, persists it, and audits")
    void flags_and_audits() {
        Tenant t = Tenant.builder().id(9L).slug("official-visa").name("x").build();

        String word = policy.flagIfWatchword(t);

        assertThat(word).isEqualTo("official");
        assertThat(t.isVerificationReviewRequired()).isTrue();
        assertThat(t.getVerificationReviewReason()).contains("official");
        verify(tenantRepository).save(t);
        verify(auditService).recordAdmin(
                eq(AuditEventTypes.TENANT_SLUG_WATCHWORD_FLAGGED), any(),
                eq(AuditEventTypes.TARGET_TENANT), eq("9"), any());
    }

    @Test
    @DisplayName("flagIfWatchword leaves a clean slug untouched — no flag, no save, no audit")
    void clean_slug_untouched() {
        Tenant t = Tenant.builder().id(9L).slug("acme").name("x").build();

        assertThat(policy.flagIfWatchword(t)).isNull();
        assertThat(t.isVerificationReviewRequired()).isFalse();
        verify(tenantRepository, never()).save(any());
        verify(auditService, never()).recordAdmin(anyString(), any(), anyString(), anyString(), any());
    }
}
