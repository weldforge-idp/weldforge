package tech.cwvermaak.weldforge.service;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import tech.cwvermaak.weldforge.config.tenant.TenantContext;
import tech.cwvermaak.weldforge.model.Role;
import tech.cwvermaak.weldforge.model.ServiceAccount;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.model.dto.RoleGrantDto;
import tech.cwvermaak.weldforge.repository.RoleRepository;
import tech.cwvermaak.weldforge.repository.ServiceAccountRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.audit.AuditEventTypes;
import tech.cwvermaak.weldforge.service.audit.AuditService;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Assigning tenant roles under one name prefix, for a credential that may do
 * nothing else.
 *
 * <p>The need: a downstream application wants its own admins to manage its own
 * roles. The only credential that could do that was a {@code TENANT_ADMIN}
 * service account, which can also delete users, reset MFA and edit OIDC
 * clients across the whole tenant. See
 * {@code docs/product/scoped-role-grants.md} for the full contract.
 *
 * <h2>Two properties this class exists to hold</h2>
 *
 * <ol>
 *   <li><b>A replace touches only the prefix.</b> Roles outside it are carried
 *       through untouched, so a credential scoped to {@code clepsydra:} can
 *       neither remove {@code staff} nor add it. That is the whole safety
 *       property; everything else here is in service of it.</li>
 *   <li><b>One bad name refuses the whole call.</b> Applying the valid names
 *       and skipping the rest would leave the caller believing it set a state
 *       it did not set, and there is no honest status code for "partly".</li>
 * </ol>
 *
 * <h2>Why the guard is here and not in a filter</h2>
 *
 * <p>{@code AppAuthorizationFilter} lets {@code /api/admin/**} through when no
 * {@code x-app-authorization} header is present, so the browser SPA can reach
 * it with a bearer token. An endpoint under that prefix is therefore <em>not
 * protected by being there</em>. This class identifies its caller explicitly
 * and refuses anything that is not a service account holding a prefix --
 * including a human super admin, who already has the full role API and does
 * not need a second path to the same data.
 */
@Service
@RequiredArgsConstructor
public class RoleGrantService {

    /**
     * Short enough to be a coincidence rather than a namespace: a one-character
     * prefix {@code c} matches {@code clepsydra:member} and also
     * {@code customer-support}.
     */
    private static final int MIN_PREFIX_LENGTH = 2;
    private static final int MAX_PREFIX_LENGTH = 64;
    private static final int MAX_ROLE_NAME_LENGTH = 128;

    private final ServiceAccountRepository serviceAccountRepository;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final AuditService auditService;

    /** The roles this caller can see on a user: the ones under its prefix. */
    @Transactional(readOnly = true)
    public RoleGrantDto list(Long userId) {
        ServiceAccount caller = requireGrantingServiceAccount();
        String prefix = caller.getRoleGrantPrefix().trim();
        User target = requireUserInTenant(userId, caller);

        return RoleGrantDto.builder()
                .userId(target.getId())
                .prefix(prefix)
                .roles(namesUnderPrefix(roleRepository.findRolesByUserId(target.getId()), prefix))
                .build();
    }

    /**
     * Replace this user's roles under the caller's prefix, leaving every other
     * role alone.
     *
     * <p>Missing roles are created rather than refused -- the pain that
     * prompted this feature was an operator creating one by hand. Creation is
     * reported in {@link RoleGrantDto#getCreated()} and audited on its own row
     * so that it is never silent, which is the real objection to create-on-use
     * and is better answered by visibility than by a flag the caller would
     * always set.
     */
    @Transactional
    public RoleGrantDto replace(Long userId, List<String> requestedNames) {
        ServiceAccount caller = requireGrantingServiceAccount();
        String prefix = caller.getRoleGrantPrefix().trim();
        Long tenantId = caller.getTenant().getId();
        User target = requireUserInTenant(userId, caller);

        List<String> wanted = validateAllUnderPrefix(requestedNames, prefix, caller, target);

        // Everything the caller may not touch, kept exactly as it is. This is
        // the safety property: read it before anything is written.
        Set<Role> untouched = new LinkedHashSet<>();
        for (Role held : roleRepository.findRolesByUserId(target.getId())) {
            if (!isUnderPrefix(held.getName(), prefix)) {
                untouched.add(held);
            }
        }

        List<String> created = new ArrayList<>();
        Set<Role> granted = new LinkedHashSet<>();
        for (String name : wanted) {
            Role role = roleRepository.findByTenantIdAndNameIgnoreCase(tenantId, name)
                    .orElseGet(() -> {
                        Role fresh = roleRepository.save(Role.builder()
                                .tenant(caller.getTenant())
                                .name(name)
                                .description("Created by service account '" + caller.getName()
                                        + "' on " + LocalDateTime.now().toLocalDate()
                                        + " via a scoped role grant.")
                                .build());
                        created.add(name);
                        auditService.recordAdmin(AuditEventTypes.ROLE_GRANT_ROLE_CREATED, null,
                                AuditEventTypes.TARGET_ROLE, name,
                                AuditService.meta("tenant", caller.getTenant().getSlug(),
                                        "prefix", prefix,
                                        "service_account", caller.getName()));
                        return fresh;
                    });
            granted.add(role);
        }

        Set<Role> before = new LinkedHashSet<>(roleRepository.findRolesByUserId(target.getId()));

        // Ordered by name for the same reason AdminService.setUserRoles orders:
        // the token's roles claim must be stable between issues, and "primary"
        // must mean something repeatable rather than whichever name the caller
        // happened to list first.
        List<Role> ordered = java.util.stream.Stream.concat(untouched.stream(), granted.stream())
                .sorted(java.util.Comparator.comparing(Role::getName, String.CASE_INSENSITIVE_ORDER))
                .distinct()
                .toList();

        target.setRoles(new LinkedHashSet<>(ordered));
        target.setRole(ordered.isEmpty() ? null : ordered.get(0));
        // Matching AdminService.setUserRoles. The bump buys nothing directly --
        // the roles that changed live only in OIDC access tokens, which
        // token_version cannot reach -- but two writers of the same data
        // behaving differently is the defect class this codebase keeps paying
        // for. One rule: roles changed, platform sessions end.
        target.setTokenVersion(target.getTokenVersion() + 1);
        userRepository.save(target);

        List<String> resulting = namesUnderPrefix(ordered, prefix);
        auditService.recordAdmin(AuditEventTypes.ROLE_GRANT_REPLACED, null,
                AuditEventTypes.TARGET_USER, String.valueOf(target.getId()),
                AuditService.meta("tenant", caller.getTenant().getSlug(),
                        "prefix", prefix,
                        "service_account", caller.getName(),
                        "target_email", target.getEmail(),
                        "roles", String.join(" ", resulting),
                        "added", String.join(" ", difference(granted, before)),
                        "removed", String.join(" ", removedUnderPrefix(before, granted, prefix)),
                        "created", String.join(" ", created)));

        return RoleGrantDto.builder()
                .userId(target.getId())
                .prefix(prefix)
                .roles(resulting)
                .created(created)
                .build();
    }

    // ---------------------------------------------------------------- guards

    /**
     * The caller must be a service account carrying a prefix. Everything else
     * is refused, including a human super admin: a tenant admin already has
     * {@code PUT /api/admin/users/{id}/roles}, and a second way to write the
     * same rows is a second thing to keep correct.
     */
    private ServiceAccount requireGrantingServiceAccount() {
        Long serviceAccountId = TenantContext.getActorServiceAccountId();
        if (serviceAccountId == null) {
            throw new AccessDeniedException(
                    "role grants require a service account token with a role grant prefix");
        }
        ServiceAccount sa = serviceAccountRepository.findById(serviceAccountId)
                .orElseThrow(() -> new AccessDeniedException("service account not found"));
        if (!sa.isEnabled()) {
            throw new AccessDeniedException("service account is disabled");
        }
        if (sa.getExpiresAt() != null && sa.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new AccessDeniedException("service account token expired");
        }
        if (sa.getRoleGrantPrefix() == null || sa.getRoleGrantPrefix().isBlank()) {
            throw new AccessDeniedException(
                    "this service account has no role grant prefix and may not assign roles");
        }
        if (sa.getTenant() == null) {
            throw new AccessDeniedException("a role granting service account must belong to a tenant");
        }
        return sa;
    }

    /**
     * A user outside this service account's tenant is "not found" rather than
     * forbidden: the caller must not learn which tenant an id lives in.
     */
    private User requireUserInTenant(Long userId, ServiceAccount caller) {
        return userRepository.findByIdAndTenantId(userId, caller.getTenant().getId())
                .orElseThrow(() -> new EntityNotFoundException("User " + userId + " not found"));
    }

    /**
     * Every requested name, validated and trimmed, or an exception and nothing
     * written. A name outside the prefix is the caller's bug rather than a
     * permissions problem, so it is an {@link IllegalArgumentException} and
     * therefore a 400 -- 403 is reserved for "this credential may not do this
     * at all", which a human has to fix.
     */
    private List<String> validateAllUnderPrefix(List<String> requested, String prefix,
                                                ServiceAccount caller, User target) {
        LinkedHashSet<String> out = new LinkedHashSet<>();
        for (String raw : requested == null ? List.<String>of() : requested) {
            String name = raw == null ? "" : raw.trim();
            if (name.isEmpty()) {
                throw refuse(caller, target, prefix, name, "a role name may not be blank");
            }
            if (name.length() > MAX_ROLE_NAME_LENGTH) {
                throw refuse(caller, target, prefix, name,
                        "a role name may be at most " + MAX_ROLE_NAME_LENGTH + " characters");
            }
            if (!isUnderPrefix(name, prefix)) {
                throw refuse(caller, target, prefix, name,
                        "role name [" + name + "] is not under this account's prefix [" + prefix
                                + "]; the whole request was refused and nothing was changed");
            }
            out.add(name);
        }
        return List.copyOf(out);
    }

    /**
     * A refusal is audited for the same reason a refused cross-tenant switch
     * is: the interesting security event is the attempt, and a request that
     * writes nothing leaves no other trace.
     */
    private IllegalArgumentException refuse(ServiceAccount caller, User target, String prefix,
                                            String offendingName, String message) {
        auditService.recordAdmin(AuditEventTypes.ROLE_GRANT_REFUSED, null,
                AuditEventTypes.TARGET_USER, String.valueOf(target.getId()),
                AuditService.meta("tenant", caller.getTenant().getSlug(),
                        "prefix", prefix,
                        "service_account", caller.getName(),
                        "refused_name", offendingName));
        return new IllegalArgumentException(message);
    }

    // ----------------------------------------------------------------- bits

    /**
     * Case-insensitive, and not as a convenience. Role names are already
     * unique without regard to case, so a case-sensitive test here would let
     * {@code Clepsydra:member} sit inside the namespace while being invisible
     * to a listing of it -- and therefore impossible to remove through the API
     * that owns the namespace.
     */
    static boolean isUnderPrefix(String roleName, String prefix) {
        if (roleName == null || prefix == null) return false;
        return roleName.toLowerCase(Locale.ROOT).startsWith(prefix.toLowerCase(Locale.ROOT));
    }

    /** Validation for the prefix itself, used when a service account is written. */
    public static String validatePrefix(String raw) {
        if (raw == null) return null;
        String prefix = raw.trim();
        if (prefix.isEmpty()) return null;   // blank clears the capability
        if (prefix.length() < MIN_PREFIX_LENGTH) {
            throw new IllegalArgumentException(
                    "roleGrantPrefix must be at least " + MIN_PREFIX_LENGTH + " characters; "
                            + "a shorter one matches unrelated role names by coincidence "
                            + "rather than naming a namespace");
        }
        if (prefix.length() > MAX_PREFIX_LENGTH) {
            throw new IllegalArgumentException(
                    "roleGrantPrefix must be at most " + MAX_PREFIX_LENGTH + " characters");
        }
        for (char c : prefix.toCharArray()) {
            if (Character.isWhitespace(c)) {
                throw new IllegalArgumentException(
                        "roleGrantPrefix may not contain whitespace: a role name with a space "
                                + "in it is one nobody can address cleanly");
            }
        }
        return prefix;
    }

    private static List<String> namesUnderPrefix(List<Role> roles, String prefix) {
        return roles.stream()
                .map(Role::getName)
                .filter(n -> isUnderPrefix(n, prefix))
                .sorted(String.CASE_INSENSITIVE_ORDER)
                .toList();
    }

    private static List<String> difference(Set<Role> granted, Set<Role> before) {
        Set<String> had = before.stream().map(Role::getName).collect(java.util.stream.Collectors.toSet());
        return granted.stream().map(Role::getName).filter(n -> !had.contains(n)).sorted().toList();
    }

    private static List<String> removedUnderPrefix(Set<Role> before, Set<Role> granted, String prefix) {
        Set<String> keeping = granted.stream().map(Role::getName)
                .collect(java.util.stream.Collectors.toSet());
        return before.stream().map(Role::getName)
                .filter(n -> isUnderPrefix(n, prefix))
                .filter(n -> !keeping.contains(n))
                .sorted().toList();
    }
}
