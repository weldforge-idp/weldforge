package tech.cwvermaak.weldforge.config.saml;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.weldforge.model.AuthProvider;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.TenantSamlProvider;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.ScimGroupRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.TenantSamlProviderRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.GroupRoleMappingService;
import tech.cwvermaak.weldforge.service.federation.FederationRulesEngine;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Post-SAML-login JIT provisioning. The registration id
 * ({@code {slug}-saml-{providerKey}}) tells us which tenant the user belongs
 * to, so there is no way for a SAML assertion from tenant A's IdP to end up
 * creating a user in tenant B.
 *
 * <p>Its own service, in its own transaction, because the caller is a Spring
 * Security success handler in the filter chain, outside open-in-view: before
 * WF-3 this ran there with detached entities, so the first lazy collection
 * (a group's members) threw and the catch around it swallowed the failure.
 * {@link SamlUserProvisioningSuccessHandler} then issues the session through
 * {@code AuthService} in a separate transaction, as social sign-in does.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SamlUpstreamProvisioner {

    private final TenantRepository tenantRepository;
    private final TenantSamlProviderRepository samlRepository;
    private final UserRepository userRepository;
    private final ScimGroupRepository scimGroupRepository;
    private final GroupRoleMappingService groupRoleMappingService;
    private final FederationRulesEngine federationRulesEngine;
    private final tech.cwvermaak.weldforge.service.TenantSeatService seatService;

    /**
     * Provision or update the account the assertion names.
     *
     * @return the address of the account to sign in, or empty when the
     *         assertion is unusable (unknown tenant, no address)
     * @throws tech.cwvermaak.weldforge.service.SeatLimitExceededException when
     *         a new account would exceed the tenant's seat cap
     */
    @Transactional
    public Optional<String> provision(Saml2AuthenticatedPrincipal principal,
                                      String tenantSlug, String providerKey) {
        Optional<Tenant> tenantOpt = tenantRepository.findBySlug(tenantSlug);
        if (tenantOpt.isEmpty()) return Optional.empty();
        Tenant tenant = tenantOpt.get();

        TenantSamlProvider cfg = samlRepository
                .findByTenantIdAndProviderKey(tenant.getId(), providerKey)
                .orElse(null);
        String emailAttr = cfg != null ? cfg.getEmailAttribute() : "email";
        String nameAttr  = cfg != null ? cfg.getNameAttribute()  : "name";

        // Build a claim bag from the SAML assertion so the federation
        // engine (PRD FED-02/04) sees the same view the rules were
        // authored against.
        Map<String, Object> claims = principalToClaims(principal);
        Map<String, Object> transformed = federationRulesEngine.transformClaims(tenant, claims);

        String email = (String) transformed.getOrDefault("email", firstAttribute(principal, emailAttr));
        if (email == null) {
            // Fall back to the NameID — many IdPs put the email there.
            email = principal.getName();
        }
        if (email == null || email.isBlank()) {
            log.warn("SAML assertion for tenant {} provider {} carried no usable email claim",
                    tenantSlug, providerKey);
            return Optional.empty();
        }
        String name = (String) transformed.getOrDefault("name", firstAttribute(principal, nameAttr));

        // FED-02: prefer tenant-configured matching rules, fall back to
        // email lookup if no rule matches (or none are configured).
        final String finalEmail = email;
        User user = federationRulesEngine.matchUser(tenant, claims)
                .or(() -> userRepository.findByTenantIdAndEmailIgnoreCase(tenant.getId(), finalEmail))
                .orElseGet(() -> User.builder()
                        .tenant(tenant)
                        .email(finalEmail)
                        .username(finalEmail)
                        .provider(AuthProvider.SAML)
                        .providerId(principal.getName() != null ? principal.getName() : finalEmail)
                        .build());

        // A deactivated account is left exactly as it is: the upstream does
        // not get to rename it or put it in groups. The session step refuses
        // it and records why.
        if (user.getId() != null && !user.isActive()) {
            return Optional.of(user.getEmail());
        }

        // JIT provisioning consumes a seat; an existing user re-authenticating
        // does not. The handler turns a refusal into the login page's error.
        if (user.getId() == null) {
            seatService.assertCapacity(tenant);
        }

        if (name != null) user.setName(name);
        if (user.getEmail() == null) user.setEmail(email);
        userRepository.save(user);

        // Extract group claims from the SAML assertion and sync memberships
        syncSamlGroups(principal, tenant, user);

        // Apply group-role mappings
        groupRoleMappingService.applyMappings(tenant.getId(), user.getId());
        return Optional.of(user.getEmail());
    }

    private void syncSamlGroups(Saml2AuthenticatedPrincipal principal, Tenant tenant, User user) {
        List<Object> groupValues = principal.getAttribute("groups");
        if (groupValues == null || groupValues.isEmpty()) return;

        for (Object gv : groupValues) {
            if (gv == null) continue;
            String groupName = gv.toString();
            if (groupName.isBlank()) continue;

            scimGroupRepository.findByTenantIdAndNameIgnoreCase(tenant.getId(), groupName)
                    .ifPresent(group -> {
                        boolean alreadyMember = group.getMembers().stream()
                                .anyMatch(m -> m.getId().equals(user.getId()));
                        if (!alreadyMember) {
                            group.getMembers().add(user);
                            scimGroupRepository.save(group);
                        }
                    });
        }
    }

    private static Map<String, Object> principalToClaims(Saml2AuthenticatedPrincipal principal) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("nameId", principal.getName());
        Map<String, List<Object>> attrs = principal.getAttributes();
        if (attrs != null) {
            for (Map.Entry<String, List<Object>> e : attrs.entrySet()) {
                List<Object> v = e.getValue();
                if (v == null || v.isEmpty()) continue;
                claims.put(e.getKey(), v.size() == 1 ? v.get(0) : v);
            }
        }
        return new HashMap<>(claims);
    }

    private static String firstAttribute(Saml2AuthenticatedPrincipal principal, String key) {
        if (key == null) return null;
        List<Object> values = principal.getAttribute(key);
        if (values == null || values.isEmpty()) return null;
        Object v = values.get(0);
        return v == null ? null : v.toString();
    }
}
