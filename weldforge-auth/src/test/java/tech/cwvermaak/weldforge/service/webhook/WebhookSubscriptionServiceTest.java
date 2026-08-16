package tech.cwvermaak.weldforge.service.webhook;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import tech.cwvermaak.weldforge.config.tenant.TenantAccessor;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.dto.WebhookSubscriptionDto;
import tech.cwvermaak.weldforge.repository.WebhookSubscriptionRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * B-LEGACY-1: webhook subscription creation must reject SSRF-prone target URLs
 * (internal/loopback/metadata, non-http schemes) at config time.
 */
class WebhookSubscriptionServiceTest {

    private TenantAccessor tenantAccessor;
    private WebhookSubscriptionRepository repository;
    private WebhookSubscriptionService service;

    @BeforeEach
    void setUp() {
        tenantAccessor = mock(TenantAccessor.class);
        repository = mock(WebhookSubscriptionRepository.class);
        service = new WebhookSubscriptionService(tenantAccessor, repository);
        when(tenantAccessor.requireTenant()).thenReturn(Tenant.builder().id(1L).slug("acme").name("Acme").build());
        when(repository.save(any())).thenAnswer(inv -> inv.getArgument(0));
    }

    @Test
    @DisplayName("create accepts a public https target")
    void create_publicTarget_ok() {
        WebhookSubscriptionDto dto = WebhookSubscriptionDto.builder()
                .name("ok").targetUrl("https://1.1.1.1/hook").build();

        WebhookSubscriptionDto out = service.create(dto);

        assertThat(out.getTargetUrl()).isEqualTo("https://1.1.1.1/hook");
        verify(repository).save(any());
    }

    @Test
    @DisplayName("create rejects a metadata/internal target and never persists")
    void create_internalTarget_rejected() {
        WebhookSubscriptionDto dto = WebhookSubscriptionDto.builder()
                .name("evil").targetUrl("http://169.254.169.254/latest/meta-data/").build();

        assertThatThrownBy(() -> service.create(dto))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("not allowed");

        verify(repository, never()).save(any());
    }

    @Test
    @DisplayName("create rejects a loopback target and a non-http scheme")
    void create_loopbackAndScheme_rejected() {
        assertThatThrownBy(() -> service.create(WebhookSubscriptionDto.builder()
                .name("lo").targetUrl("http://127.0.0.1:9000/admin").build()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.create(WebhookSubscriptionDto.builder()
                .name("file").targetUrl("file:///etc/passwd").build()))
                .isInstanceOf(IllegalArgumentException.class);

        verify(repository, never()).save(any());
    }
}
