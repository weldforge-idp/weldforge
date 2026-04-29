package tech.cwvermaak.intellisso.service.ldap;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.intellisso.model.AuthProvider;
import tech.cwvermaak.intellisso.model.Tenant;
import tech.cwvermaak.intellisso.model.TenantLdapProvider;
import tech.cwvermaak.intellisso.model.User;
import tech.cwvermaak.intellisso.repository.TenantLdapProviderRepository;
import tech.cwvermaak.intellisso.repository.UserRepository;
import tech.cwvermaak.intellisso.service.federation.FederationRulesEngine;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Attempts upstream LDAP / AD authentication for a tenant (PRD DIR-01, DIR-02).
 *
 * <p>Flow:
 * <ol>
 *   <li>Walk the tenant's enabled {@link TenantLdapProvider}s in order.</li>
 *   <li>Delegate actual bind + attribute fetch to {@link LdapClient}.</li>
 *   <li>Build a flat claim bag from the returned attributes.</li>
 *   <li>Resolve or create the local {@link User} using the same
 *       {@link FederationRulesEngine} the SAML path uses, so matching
 *       rules and claim transforms (Epic C) apply here too.</li>
 * </ol>
 *
 * <p>A "failure" — bad credentials, user not in LDAP, or directory
 * unreachable — always returns {@link Optional#empty()} so the caller
 * can fall back to the next strategy (typically local password auth).
 * This preserves break-glass access for tenants whose directory goes down.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class LdapUpstreamService {

    private final TenantLdapProviderRepository providerRepository;
    private final LdapClient ldapClient;
    private final UserRepository userRepository;
    private final FederationRulesEngine federationRulesEngine;

    @Transactional
    public Optional<User> authenticate(Tenant tenant, String username, String password) {
        if (tenant == null || username == null || password == null) return Optional.empty();
        List<TenantLdapProvider> providers = providerRepository.findByTenantIdAndEnabledTrue(tenant.getId());
        if (providers.isEmpty()) return Optional.empty();

        for (TenantLdapProvider provider : providers) {
            Optional<LdapClient.LdapAttributes> attrs = ldapClient.authenticate(provider, username, password);
            if (attrs.isEmpty()) continue;

            User user = resolveOrProvision(tenant, provider, attrs.get(), username);
            if (user != null) return Optional.of(user);
        }
        return Optional.empty();
    }

    /**
     * Verify a provider's configuration without a user credential. Used
     * by the admin "test connection" button.
     */
    public boolean testConnection(TenantLdapProvider provider) {
        return ldapClient.testConnection(provider);
    }

    // ---- Internals -------------------------------------------------

    private User resolveOrProvision(Tenant tenant,
                                    TenantLdapProvider provider,
                                    LdapClient.LdapAttributes attrs,
                                    String submittedUsername) {
        Map<String, Object> claims = buildClaims(provider, attrs, submittedUsername);
        // Tenant-configured federation rules run first so matching_rules
        // and claim_transforms (Epic C) apply to LDAP exactly like SAML.
        federationRulesEngine.transformClaims(tenant, claims);

        String email = firstString(attrs.attributes().get(provider.getEmailAttribute()));
        String name = firstString(attrs.attributes().get(provider.getNameAttribute()));
        String username = firstString(attrs.attributes().get(provider.getUsernameAttribute()));
        if (email == null) email = submittedUsername;
        if (username == null) username = submittedUsername;

        final String finalEmail = email;
        final String finalUsername = username;
        User user = federationRulesEngine.matchUser(tenant, claims)
                .or(() -> userRepository.findByTenantIdAndEmailIgnoreCase(tenant.getId(), finalEmail))
                .or(() -> userRepository.findByTenantIdAndUsernameIgnoreCase(tenant.getId(), finalUsername))
                .orElseGet(() -> User.builder()
                        .tenant(tenant)
                        .email(finalEmail)
                        .username(finalUsername)
                        .provider(AuthProvider.LDAP)
                        .providerId(attrs.dn())
                        .build());

        if (name != null) user.setName(name);
        if (user.getEmail() == null) user.setEmail(email);
        if (user.getProvider() == null) user.setProvider(AuthProvider.LDAP);
        if (user.getProviderId() == null) user.setProviderId(attrs.dn());
        return userRepository.save(user);
    }

    private static Map<String, Object> buildClaims(TenantLdapProvider provider,
                                                   LdapClient.LdapAttributes attrs,
                                                   String submittedUsername) {
        Map<String, Object> claims = new HashMap<>(attrs.attributes());
        claims.put("dn", attrs.dn());
        claims.put("submitted_username", submittedUsername);
        claims.put("provider_type", provider.getProviderType().name());
        return claims;
    }

    private static String firstString(Object raw) {
        if (raw == null) return null;
        if (raw instanceof List<?> list) {
            return list.isEmpty() ? null : String.valueOf(list.get(0));
        }
        return raw.toString();
    }
}
