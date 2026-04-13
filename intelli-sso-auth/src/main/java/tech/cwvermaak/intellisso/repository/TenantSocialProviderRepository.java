package tech.cwvermaak.intellisso.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import tech.cwvermaak.intellisso.model.SocialProviderType;
import tech.cwvermaak.intellisso.model.TenantSocialProvider;

import java.util.List;
import java.util.Optional;

public interface TenantSocialProviderRepository
        extends JpaRepository<TenantSocialProvider, Long> {

    List<TenantSocialProvider> findByTenantId(Long tenantId);

    List<TenantSocialProvider> findByTenantIdAndEnabledTrue(Long tenantId);

    Optional<TenantSocialProvider> findByTenantIdAndProvider(Long tenantId, SocialProviderType provider);

    Optional<TenantSocialProvider> findByTenant_SlugAndProviderAndEnabledTrue(
            String tenantSlug, SocialProviderType provider);

    List<TenantSocialProvider> findByTenant_SlugAndEnabledTrue(String tenantSlug);
}
