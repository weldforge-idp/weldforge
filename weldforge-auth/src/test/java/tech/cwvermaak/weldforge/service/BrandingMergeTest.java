package tech.cwvermaak.weldforge.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static tech.cwvermaak.weldforge.service.BrandingMerge.merge;

/**
 * Which branding wins on the login screen.
 *
 * <p>A tenant hosts several applications — cwvermaak-tech alone carries
 * KeyCrypt, NoteForge and Clepsydra — so "the tenant's branding" is the wrong
 * answer for a person signing in to one of them.
 *
 * <p>The rule that matters is KEY BY KEY. Replacing wholesale would make the
 * cheapest useful case ("our logo, your colours") the most expensive, and
 * would blank a tenant's palette the first time a client saved a single
 * field.
 */
@DisplayName("Client branding over tenant branding")
class BrandingMergeTest {

    private static Map<String, Object> map(String... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) m.put(kv[i], kv[i + 1]);
        return m;
    }

    @Test
    @DisplayName("no client branding inherits the tenant entirely")
    void inheritsWhenAbsent() {
        Map<String, Object> tenant = map("primaryColor", "#111", "logoUrl", "t.png");
        assertThat(merge(tenant, null)).isEqualTo(tenant);
    }

    @Test
    @DisplayName("a client key overlays the tenant's")
    void overlays() {
        assertThat(merge(map("primaryColor", "#111"), map("primaryColor", "#222")))
                .containsEntry("primaryColor", "#222");
    }

    @Test
    @DisplayName("keys the client does not set are kept — the whole point")
    void keepsUnsetKeys() {
        Map<String, Object> out = merge(
                map("primaryColor", "#111", "bgColor", "#000", "sansFont", "Inter"),
                map("logoUrl", "clepsydra.png"));

        assertThat(out).containsEntry("logoUrl", "clepsydra.png");
        assertThat(out).containsEntry("primaryColor", "#111");
        assertThat(out).containsEntry("bgColor", "#000");
        assertThat(out).containsEntry("sansFont", "Inter");
    }

    @Test
    @DisplayName("a blank client value does not blank the tenant's")
    void blankDoesNotClear() {
        // A half-filled client record must not wipe a tenant's palette, which
        // is what would happen on the first save of a form with empty fields.
        Map<String, Object> out = merge(map("primaryColor", "#111"), map("primaryColor", "  "));
        assertThat(out).containsEntry("primaryColor", "#111");
    }

    @Test
    @DisplayName("a null client value does not blank the tenant's either")
    void nullDoesNotClear() {
        Map<String, Object> client = new LinkedHashMap<>();
        client.put("primaryColor", null);
        assertThat(merge(map("primaryColor", "#111"), client))
                .containsEntry("primaryColor", "#111");
    }

    @Test
    @DisplayName("a client may introduce a key the tenant never set")
    void addsNewKeys() {
        assertThat(merge(map("primaryColor", "#111"), map("tagline", "Time, measured")))
                .containsEntry("tagline", "Time, measured");
    }

    @Test
    @DisplayName("no tenant branding at all still yields the client's")
    void tenantMayBeNull() {
        assertThat(merge(null, map("logoUrl", "c.png"))).containsEntry("logoUrl", "c.png");
    }

    @Test
    @DisplayName("both absent is empty, never null")
    void bothAbsent() {
        assertThat(merge(null, null)).isNotNull().isEmpty();
    }

    @Test
    @DisplayName("the inputs are not mutated")
    void doesNotMutateInputs() {
        Map<String, Object> tenant = map("primaryColor", "#111");
        Map<String, Object> client = map("logoUrl", "c.png");

        merge(tenant, client);

        assertThat(tenant).containsOnlyKeys("primaryColor");
        assertThat(client).containsOnlyKeys("logoUrl");
    }

    @Test
    @DisplayName("non-string values survive — branding is free-form JSON")
    void nonStringValues() {
        Map<String, Object> client = new LinkedHashMap<>();
        client.put("theme", "light");
        client.put("compact", Boolean.TRUE);
        assertThat(merge(map("theme", "dark"), client))
                .containsEntry("theme", "light")
                .containsEntry("compact", Boolean.TRUE);
    }
}
