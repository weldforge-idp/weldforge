package tech.cwvermaak.weldforge.service.oidc;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import tech.cwvermaak.weldforge.config.tenant.TenantAccessor;
import tech.cwvermaak.weldforge.model.OidcScope;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.dto.OidcScopeDto;
import tech.cwvermaak.weldforge.repository.OidcScopeRepository;
import tech.cwvermaak.weldforge.service.audit.AuditEventTypes;
import tech.cwvermaak.weldforge.service.audit.AuditService;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The per-tenant scope registry.
 *
 * <p>Scope names are free strings and the consent screen printed them raw, so
 * a person approving {@code board.view} was approving a string. For an agent
 * acting on someone's behalf that screen is the only place the permission is
 * ever explained, which is what this registry is for.
 */
class OidcScopeServiceTest {

    private OidcScopeRepository repository;
    private TenantAccessor tenantAccessor;
    private AuditService auditService;
    private OidcScopeService service;
    private Tenant acme;

    @BeforeEach
    void setUp() {
        repository = mock(OidcScopeRepository.class);
        tenantAccessor = mock(TenantAccessor.class);
        auditService = mock(AuditService.class);
        service = new OidcScopeService(repository, tenantAccessor, auditService);

        acme = Tenant.builder().id(1L).slug("acme").name("Acme").build();
        when(tenantAccessor.requireTenant()).thenReturn(acme);
        when(tenantAccessor.requireTenantId()).thenReturn(1L);
        when(repository.save(any(OidcScope.class)))
                .thenAnswer(inv -> inv.getArgument(0));
    }

    private static OidcScope scope(String name, Map<String, String> descriptions) {
        return OidcScope.builder().tenant(Tenant.builder().id(1L).build())
                .name(name).descriptions(new LinkedHashMap<>(descriptions)).build();
    }

    private void registry(OidcScope... rows) {
        when(repository.findByTenantIdOrderByNameAsc(1L)).thenReturn(List.of(rows));
        for (OidcScope row : rows) {
            when(repository.findByTenantIdAndName(1L, row.getName()))
                    .thenReturn(Optional.of(row));
        }
    }

    @Nested
    @DisplayName("describe — the words the consent screen shows")
    class Describe {

        @Test
        @DisplayName("a described scope resolves to the language the browser asked for")
        void resolves_requested_language() {
            registry(scope("board.view", Map.of("en", "See your board", "de", "Ihr Board sehen")));

            assertThat(service.describe(acme, "board.view", "de"))
                    .containsEntry("board.view", "Ihr Board sehen");
        }

        @Test
        @DisplayName("a regional tag falls back to its primary subtag")
        void regional_tag_falls_back_to_primary() {
            // The point of the fallback: a tenant writes one German
            // description, not one per German-speaking country.
            registry(scope("board.view", Map.of("de", "Ihr Board sehen")));

            assertThat(service.describe(acme, "board.view", "de-AT"))
                    .containsEntry("board.view", "Ihr Board sehen");
        }

        @Test
        @DisplayName("an unknown language falls back to English")
        void unknown_language_falls_back_to_english() {
            registry(scope("board.view", Map.of("en", "See your board")));

            assertThat(service.describe(acme, "board.view", "ja"))
                    .containsEntry("board.view", "See your board");
        }

        @Test
        @DisplayName("a scope with no description is absent, not described as its own name")
        void undescribed_scope_is_absent() {
            // The renderer distinguishes described from undescribed and shows
            // them differently. Collapsing that here would take the choice
            // away and put a bare scope name where a sentence belongs.
            registry(scope("board.view", Map.of()));

            assertThat(service.describe(acme, "board.view", "en")).isEmpty();
        }

        @Test
        @DisplayName("only the requested scopes come back")
        void only_requested_scopes() {
            registry(scope("board.view", Map.of("en", "See your board")),
                    scope("card.decide", Map.of("en", "Approve cards for you")));

            assertThat(service.describe(acme, "openid card.decide", null))
                    .containsOnlyKeys("card.decide");
        }

        @Test
        @DisplayName("no tenant, no scope and a blank scope all describe nothing")
        void degenerate_inputs() {
            assertThat(service.describe(null, "board.view", "en")).isEmpty();
            assertThat(service.describe(acme, null, "en")).isEmpty();
            assertThat(service.describe(acme, "   ", "en")).isEmpty();
        }
    }

    @Nested
    @DisplayName("preferredLanguage — reading Accept-Language")
    class PreferredLanguage {

        @Test
        @DisplayName("the first tag wins and q-values are ignored")
        void first_tag_wins() {
            assertThat(OidcScopeService.preferredLanguage("de-AT,de;q=0.9,en;q=0.8"))
                    .isEqualTo("de-at");
        }

        @Test
        @DisplayName("a wildcard expresses no preference")
        void wildcard_is_no_preference() {
            // "*" means "anything", which says nothing about what to show.
            assertThat(OidcScopeService.preferredLanguage("*")).isNull();
            assertThat(OidcScopeService.preferredLanguage("*,fr")).isEqualTo("fr");
        }

        @Test
        @DisplayName("no header is the same as no preference")
        void absent_header() {
            assertThat(OidcScopeService.preferredLanguage(null)).isNull();
            assertThat(OidcScopeService.preferredLanguage("  ")).isNull();
        }
    }

    @Nested
    @DisplayName("the admin surface")
    class Admin {

        @Test
        @DisplayName("an upsert registers the scope and audits who changed the words")
        void upsert_registers_and_audits() {
            when(repository.findByTenantIdAndName(1L, "board.view")).thenReturn(Optional.empty());

            OidcScopeDto saved = service.upsert("board.view", Map.of("EN", "  See your board  "));

            assertThat(saved.getName()).isEqualTo("board.view");
            // Language tags are case-insensitive and the text is trimmed, so
            // the lookup at consent time does not depend on how it was typed.
            assertThat(saved.getDescriptions()).containsEntry("en", "See your board");
            verify(auditService).recordAdmin(eq(AuditEventTypes.OIDC_SCOPE_UPSERT), any(),
                    eq(AuditEventTypes.TARGET_OIDC_SCOPE), eq("board.view"), any());
        }

        @Test
        @DisplayName("a blank description is dropped rather than stored")
        void blank_descriptions_are_dropped() {
            when(repository.findByTenantIdAndName(1L, "board.view")).thenReturn(Optional.empty());

            Map<String, String> words = new LinkedHashMap<>();
            words.put("en", "See your board");
            words.put("de", "   ");

            assertThat(service.upsert("board.view", words).getDescriptions())
                    .containsOnlyKeys("en");
        }

        @Test
        @DisplayName("a name with a space is refused, because it could never be requested")
        void space_in_name_is_refused() {
            // RFC 6749 delimits scopes with spaces: "board view" would arrive
            // as two scopes, neither of them this row. Refusing it here is a
            // 400 where it was typed instead of a scope that never matches.
            assertThatThrownBy(() -> service.upsert("board view", Map.of()))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("scope name");
            verify(repository, never()).save(any());
        }

        @Test
        @DisplayName("an empty name is refused")
        void empty_name_is_refused() {
            assertThatThrownBy(() -> service.upsert("   ", Map.of()))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        @DisplayName("a name longer than the column is refused before the database sees it")
        void overlong_name_is_refused() {
            assertThatThrownBy(() -> service.upsert("s".repeat(129), Map.of()))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("128");
        }

        @Test
        @DisplayName("replaceAll removes what the caller left out")
        void replace_all_removes_omitted() {
            OidcScope stale = scope("old.scope", Map.of("en", "Gone"));
            registry(stale);
            when(repository.findByTenantIdAndName(1L, "board.view")).thenReturn(Optional.empty());

            service.replaceAll(List.of(OidcScopeDto.builder()
                    .name("board.view").descriptions(Map.of("en", "See your board")).build()));

            // Replace, not merge: a screen that shows the whole list and saves
            // it means "this is the list now", and merging would make a
            // removal impossible to express.
            verify(repository).delete(stale);
        }

        @Test
        @DisplayName("deleting an unregistered scope is a 404, not a silent success")
        void delete_unknown_is_not_found() {
            when(repository.findByTenantIdAndName(1L, "nope")).thenReturn(Optional.empty());

            assertThatThrownBy(() -> service.delete("nope"))
                    .isInstanceOf(jakarta.persistence.EntityNotFoundException.class);
        }

        @Test
        @DisplayName("every write demands a tenant admin, every read an admin")
        void admin_is_required() {
            // The guards are the only thing standing between a tenant member
            // and editing what every other member is told they are agreeing
            // to. A test that only exercised the happy path would not notice
            // one going missing.
            service.list();
            verify(tenantAccessor).requireAnyAdmin();

            when(repository.findByTenantIdAndName(anyLong(), anyString()))
                    .thenReturn(Optional.of(scope("board.view", Map.of())));

            service.upsert("board.view", Map.of());
            service.delete("board.view");
            service.replaceAll(List.of());

            verify(tenantAccessor, org.mockito.Mockito.times(3)).requireTenantAdmin();
        }
    }
}
