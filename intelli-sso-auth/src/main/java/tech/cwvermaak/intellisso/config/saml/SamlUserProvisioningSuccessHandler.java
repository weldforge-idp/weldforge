package tech.cwvermaak.intellisso.config.saml;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import tech.cwvermaak.intellisso.model.AuthProvider;
import tech.cwvermaak.intellisso.model.ScimGroup;
import tech.cwvermaak.intellisso.model.Tenant;
import tech.cwvermaak.intellisso.model.TenantSamlProvider;
import tech.cwvermaak.intellisso.model.User;
import tech.cwvermaak.intellisso.repository.ScimGroupRepository;
import tech.cwvermaak.intellisso.repository.TenantRepository;
import tech.cwvermaak.intellisso.repository.TenantSamlProviderRepository;
import tech.cwvermaak.intellisso.repository.UserRepository;
import tech.cwvermaak.intellisso.service.GroupRoleMappingService;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

/**
 * Post-SAML-login JIT provisioning. The registration id
 * ({@code {slug}-saml-{providerKey}}) tells us which tenant the user belongs
 * to, so there is no way for a SAML assertion from tenant A's IdP to end up
 * creating a user in tenant B.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class SamlUserProvisioningSuccessHandler
        extends SavedRequestAwareAuthenticationSuccessHandler {

    private final TenantRepository tenantRepository;
    private final TenantSamlProviderRepository samlRepository;
    private final UserRepository userRepository;
    private final ScimGroupRepository scimGroupRepository;
    private final GroupRoleMappingService groupRoleMappingService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws ServletException, IOException {
        try {
            provision(authentication);
        } catch (Exception e) {
            log.error("SAML user provisioning failed: {}", e.getMessage(), e);
        }
        super.onAuthenticationSuccess(request, response, authentication);
    }

    private void provision(Authentication authentication) {
        if (!(authentication.getPrincipal() instanceof Saml2AuthenticatedPrincipal principal)) {
            return;
        }
        String registrationId = principal.getRelyingPartyRegistrationId();
        if (registrationId == null) return;

        int idx = registrationId.indexOf(DatabaseRelyingPartyRegistrationRepository.SAML_INFIX);
        if (idx <= 0) return;

        String tenantSlug  = registrationId.substring(0, idx);
        String providerKey = registrationId.substring(
                idx + DatabaseRelyingPartyRegistrationRepository.SAML_INFIX.length());

        Optional<Tenant> tenantOpt = tenantRepository.findBySlug(tenantSlug);
        if (tenantOpt.isEmpty()) return;
        Tenant tenant = tenantOpt.get();

        TenantSamlProvider cfg = samlRepository
                .findByTenantIdAndProviderKey(tenant.getId(), providerKey)
                .orElse(null);
        String emailAttr = cfg != null ? cfg.getEmailAttribute() : "email";
        String nameAttr  = cfg != null ? cfg.getNameAttribute()  : "name";

        String email = firstAttribute(principal, emailAttr);
        if (email == null) {
            // Fall back to the NameID — many IdPs put the email there.
            email = principal.getName();
        }
        if (email == null || email.isBlank()) {
            log.warn("SAML assertion for tenant {} provider {} carried no usable email claim",
                    tenantSlug, providerKey);
            return;
        }
        String name = firstAttribute(principal, nameAttr);

        final String finalEmail = email;
        User user = userRepository.findByTenantIdAndEmailIgnoreCase(tenant.getId(), email)
                .orElseGet(() -> User.builder()
                        .tenant(tenant)
                        .email(finalEmail)
                        .username(finalEmail)
                        .provider(AuthProvider.SAML)
                        .providerId(principal.getName() != null ? principal.getName() : finalEmail)
                        .build());

        if (name != null) user.setName(name);
        userRepository.save(user);

        // Extract group claims from the SAML assertion and sync memberships
        syncSamlGroups(principal, tenant, user);

        // Apply group-role mappings
        groupRoleMappingService.applyMappings(tenant.getId(), user.getId());
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

    private static String firstAttribute(Saml2AuthenticatedPrincipal principal, String key) {
        if (key == null) return null;
        List<Object> values = principal.getAttribute(key);
        if (values == null || values.isEmpty()) return null;
        Object v = values.get(0);
        return v == null ? null : v.toString();
    }
}
