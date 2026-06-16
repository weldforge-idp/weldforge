package tech.cwvermaak.weldforge.service.oidc;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import tech.cwvermaak.weldforge.config.tenant.TenantAccessor;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.dto.OidcClientDto;
import tech.cwvermaak.weldforge.repository.OidcClientRepository;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * B-OIDC-4: redirect_uri validation at client registration (RFC 9700 / RFC 8252).
 */
class OidcClientServiceTest {

    private TenantAccessor tenantAccessor;
    private OidcClientRepository repository;
    private OidcClientService service;

    @BeforeEach
    void setUp() {
        tenantAccessor = mock(TenantAccessor.class);
        repository = mock(OidcClientRepository.class);
        service = new OidcClientService(tenantAccessor, repository);
        when(tenantAccessor.requireTenant()).thenReturn(Tenant.builder().id(1L).slug("acme").name("Acme").build());
        when(repository.findByTenantIdAndClientId(anyLong(), anyString())).thenReturn(Optional.empty());
        when(repository.save(any())).thenAnswer(inv -> inv.getArgument(0));
    }

    private OidcClientDto dto(String redirectUri) {
        return OidcClientDto.builder()
                .name("app")
                .redirectUris(List.of(redirectUri))
                .scopes(List.of("openid"))
                .grantTypes(List.of("authorization_code"))
                .build();
    }

    @Test
    @DisplayName("accepts an https redirect_uri and a loopback http one")
    void acceptsValid() {
        assertThatCode(() -> service.create(dto("https://app.acme.test/cb"))).doesNotThrowAnyException();
        assertThatCode(() -> service.create(dto("http://localhost:3000/cb"))).doesNotThrowAnyException();
        assertThatCode(() -> service.create(dto("com.acme.app:/oauth2redirect"))).doesNotThrowAnyException();
    }

    @Test
    @DisplayName("rejects plain http to a non-loopback host")
    void rejectsHttpNonLoopback() {
        assertThatThrownBy(() -> service.create(dto("http://evil.example.com/cb")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("https");
        verify(repository, never()).save(any());
    }

    @Test
    @DisplayName("rejects a redirect_uri carrying a fragment")
    void rejectsFragment() {
        assertThatThrownBy(() -> service.create(dto("https://app.acme.test/cb#frag")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("fragment");
    }

    @Test
    @DisplayName("rejects a relative (non-absolute) redirect_uri")
    void rejectsRelative() {
        assertThatThrownBy(() -> service.create(dto("/callback")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("absolute");
    }
}
