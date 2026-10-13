package tech.cwvermaak.weldforge.service.oidc;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.weldforge.config.tenant.TenantAccessor;
import tech.cwvermaak.weldforge.model.OidcScope;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.dto.OidcScopeDto;
import tech.cwvermaak.weldforge.repository.OidcScopeRepository;
import tech.cwvermaak.weldforge.service.audit.AuditEventTypes;
import tech.cwvermaak.weldforge.service.audit.AuditService;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * The words a tenant has registered for its scopes.
 *
 * <p>Two callers, and they want different things from the same rows: the
 * consent screen wants the description for the language the browser asked
 * for, and the discovery document wants the names.
 */
@Service
@RequiredArgsConstructor
public class OidcScopeService {

    /**
     * The longest a scope name may be, matching {@code oidc_scopes.name}. A
     * longer one would be refused by the database with a 500 rather than told
     * to the admin who typed it.
     */
    private static final int MAX_NAME_LENGTH = 128;

    private final OidcScopeRepository scopeRepository;
    private final TenantAccessor tenantAccessor;
    private final AuditService auditService;

    /**
     * Scope name to description, for the scopes in a space-delimited request.
     *
     * <p>Scopes with no registered description are simply absent from the map
     * rather than present with their own name as the value: the renderer
     * distinguishes "described" from "not described" and shows them
     * differently, and collapsing that here would take the choice away.
     *
     * @param acceptLanguage the raw {@code Accept-Language} header, or null
     */
    @Transactional(readOnly = true)
    public Map<String, String> describe(Tenant tenant, String scope, String acceptLanguage) {
        if (tenant == null || scope == null || scope.isBlank()) return Map.of();

        List<String> requested = Arrays.stream(scope.split("\\s+"))
                .filter(s -> !s.isBlank())
                .toList();
        if (requested.isEmpty()) return Map.of();

        String language = preferredLanguage(acceptLanguage);
        Map<String, String> out = new LinkedHashMap<>();
        for (OidcScope registered : scopeRepository.findByTenantIdOrderByNameAsc(tenant.getId())) {
            if (!requested.contains(registered.getName())) continue;
            String described = registered.describe(language);
            if (described != null && !described.isBlank()) {
                out.put(registered.getName(), described);
            }
        }
        return out;
    }

    /** Every scope name this tenant has registered, for {@code scopes_supported}. */
    @Transactional(readOnly = true)
    public List<String> registeredNames(Long tenantId) {
        return scopeRepository.findByTenantIdOrderByNameAsc(tenantId).stream()
                .map(OidcScope::getName)
                .toList();
    }

    /**
     * The caller's first choice of language from an {@code Accept-Language} header.
     *
     * <p>Deliberately simple: the first tag listed, ignoring q-values. Getting
     * full RFC 9110 weighting right would mean ranking languages we do not have
     * descriptions for anyway, and {@link OidcScope#describe} already falls back
     * through the primary subtag to English. A header we cannot parse yields
     * null, which is the same as not sending one.
     */
    static String preferredLanguage(String acceptLanguage) {
        if (acceptLanguage == null || acceptLanguage.isBlank()) return null;
        for (String part : acceptLanguage.split(",")) {
            String tag = part.split(";")[0].trim();
            // "*" means "anything", which tells us nothing about a preference.
            if (!tag.isEmpty() && !"*".equals(tag)) {
                return tag.toLowerCase(Locale.ROOT);
            }
        }
        return null;
    }

    // ---- Admin surface ----------------------------------------------
    //
    // Without these the registry is a table nobody can write to, and the
    // feature reads as shipped while being unusable -- the same gap the
    // resources list had before it was caught in #149.

    /** Every scope this tenant has registered, names and words. */
    @Transactional(readOnly = true)
    public List<OidcScopeDto> list() {
        tenantAccessor.requireAnyAdmin();
        return scopeRepository.findByTenantIdOrderByNameAsc(tenantAccessor.requireTenantId())
                .stream().map(OidcScopeService::toDto).toList();
    }

    /**
     * Register a scope, or replace the words registered for it.
     *
     * <p>Upsert rather than separate create and update: the admin screen edits
     * a name and its words together, and a create that 409s because the name
     * is already registered would ask its user a question they cannot answer.
     */
    @Transactional
    public OidcScopeDto upsert(String rawName, Map<String, String> descriptions) {
        tenantAccessor.requireTenantAdmin();
        Tenant tenant = tenantAccessor.requireTenant();
        String name = validName(rawName);

        OidcScope row = scopeRepository.findByTenantIdAndName(tenant.getId(), name)
                .orElseGet(() -> OidcScope.builder().tenant(tenant).name(name).build());
        row.setDescriptions(cleanDescriptions(descriptions));
        OidcScope saved = scopeRepository.save(row);

        auditService.recordAdmin(AuditEventTypes.OIDC_SCOPE_UPSERT, null,
                AuditEventTypes.TARGET_OIDC_SCOPE, name,
                AuditService.meta("tenant", tenant.getSlug(),
                        "languages", String.join(",", saved.getDescriptions().keySet())));
        return toDto(saved);
    }

    /**
     * Forget a scope's registration.
     *
     * <p>The scope itself keeps working: this registry explains scopes, it
     * does not grant them. What a client may ask for is the client's own scope
     * list, and deleting a row here only takes the words away.
     */
    @Transactional
    public void delete(String rawName) {
        tenantAccessor.requireTenantAdmin();
        Tenant tenant = tenantAccessor.requireTenant();
        String name = validName(rawName);

        OidcScope row = scopeRepository.findByTenantIdAndName(tenant.getId(), name)
                .orElseThrow(() -> new EntityNotFoundException(
                        "scope " + name + " is not registered"));
        scopeRepository.delete(row);

        auditService.recordAdmin(AuditEventTypes.OIDC_SCOPE_DELETE, null,
                AuditEventTypes.TARGET_OIDC_SCOPE, name,
                AuditService.meta("tenant", tenant.getSlug()));
    }

    /**
     * Replace a tenant's scope registry with exactly this set.
     *
     * <p>Replace rather than merge, because a screen that shows the whole list
     * and saves it means "this is the list now"; merging would make a removal
     * impossible to express. Two admins saving the whole list at once do
     * overwrite each other, which is why {@link #upsert} and {@link #delete}
     * exist beside it -- prefer those unless the caller really is saving the
     * entire registry.
     */
    @Transactional
    public List<OidcScopeDto> replaceAll(List<OidcScopeDto> scopes) {
        tenantAccessor.requireTenantAdmin();
        Tenant tenant = tenantAccessor.requireTenant();

        Map<String, Map<String, String>> wanted = new LinkedHashMap<>();
        for (OidcScopeDto dto : scopes == null ? List.<OidcScopeDto>of() : scopes) {
            if (dto == null) continue;
            wanted.put(validName(dto.getName()), cleanDescriptions(dto.getDescriptions()));
        }

        for (OidcScope row : scopeRepository.findByTenantIdOrderByNameAsc(tenant.getId())) {
            if (!wanted.containsKey(row.getName())) scopeRepository.delete(row);
        }

        List<OidcScopeDto> saved = new ArrayList<>();
        for (Map.Entry<String, Map<String, String>> e : wanted.entrySet()) {
            OidcScope row = scopeRepository.findByTenantIdAndName(tenant.getId(), e.getKey())
                    .orElseGet(() -> OidcScope.builder()
                            .tenant(tenant).name(e.getKey()).build());
            row.setDescriptions(e.getValue());
            saved.add(toDto(scopeRepository.save(row)));
        }

        auditService.recordAdmin(AuditEventTypes.OIDC_SCOPE_REPLACE_ALL, null,
                AuditEventTypes.TARGET_OIDC_SCOPE, tenant.getSlug(),
                AuditService.meta("tenant", tenant.getSlug(),
                        "scopes", String.join(" ", wanted.keySet())));
        return saved;
    }

    // ---- Helpers ------------------------------------------------------

    /**
     * A scope name that can actually be asked for.
     *
     * <p>RFC 6749 section 3.3 delimits scopes with spaces, so a name holding
     * one can never be requested -- it would arrive as two scopes, neither of
     * them this row. The quote and the backslash are excluded by the same
     * grammar. Checking here turns an unusable registration into a 400 where
     * someone typed it, instead of a scope that silently never matches.
     */
    static String validName(String raw) {
        String name = raw == null ? "" : raw.trim();
        if (name.isEmpty()) {
            throw new IllegalArgumentException("scope name is required");
        }
        if (name.length() > MAX_NAME_LENGTH) {
            throw new IllegalArgumentException(
                    "scope name must be at most " + MAX_NAME_LENGTH + " characters");
        }
        for (char c : name.toCharArray()) {
            boolean allowed = c == 0x21 || (c >= 0x23 && c <= 0x5B) || (c >= 0x5D && c <= 0x7E);
            if (!allowed) {
                throw new IllegalArgumentException(
                        "scope name may not contain [" + c + "]: an RFC 6749 scope token is "
                                + "printable ASCII without space, quote or backslash");
            }
        }
        return name;
    }

    /**
     * Language tag to description, with the blanks dropped.
     *
     * <p>A blank description is the same as none -- {@link OidcScope#describe}
     * skips it either way -- and keeping it would let the consent screen and
     * the admin screen disagree about whether a scope is described.
     */
    private static Map<String, String> cleanDescriptions(Map<String, String> raw) {
        Map<String, String> out = new LinkedHashMap<>();
        if (raw == null) return out;
        raw.forEach((tag, text) -> {
            if (tag == null || tag.isBlank() || text == null || text.isBlank()) return;
            out.put(tag.trim().toLowerCase(Locale.ROOT), text.trim());
        });
        return out;
    }

    private static OidcScopeDto toDto(OidcScope row) {
        return OidcScopeDto.builder()
                .id(row.getId())
                .name(row.getName())
                .descriptions(new LinkedHashMap<>(
                        row.getDescriptions() == null ? Map.of() : row.getDescriptions()))
                .createdAt(row.getCreatedAt())
                .updatedAt(row.getUpdatedAt())
                .build();
    }
}
