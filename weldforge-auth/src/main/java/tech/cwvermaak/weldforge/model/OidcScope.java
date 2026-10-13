package tech.cwvermaak.weldforge.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * A scope a tenant has registered, and what it means in words.
 *
 * <p>Scope names are free strings and the consent screen printed them raw, so
 * a person approving {@code board.view} was approving a string. The registry
 * exists so the screen can say what the permission actually is — and for a
 * go-between acting on someone's behalf, that screen is the only place the
 * permission is ever explained.
 *
 * <p>Per tenant rather than per client: a scope means the same thing across a
 * tenant, and a tenant routinely hosts several clients. Registering the
 * meaning once stops two clients describing one permission two ways.
 */
@Entity
@Table(name = "oidc_scopes")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OidcScope {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @Column(nullable = false, length = 128)
    private String name;

    /**
     * Language tag to description, e.g. {@code {"en": "See your board"}}.
     *
     * <p>Never null — an empty map is a scope registered with no words yet,
     * which displays as its own name and so is no worse than not registering
     * it at all.
     */
    @org.hibernate.annotations.JdbcTypeCode(org.hibernate.type.SqlTypes.JSON)
    @Column(name = "descriptions", nullable = false, columnDefinition = "jsonb")
    @Builder.Default
    private Map<String, String> descriptions = new LinkedHashMap<>();

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @PrePersist
    void onCreate() {
        LocalDateTime now = LocalDateTime.now();
        if (createdAt == null) createdAt = now;
        updatedAt = now;
        if (descriptions == null) descriptions = new LinkedHashMap<>();
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = LocalDateTime.now();
        if (descriptions == null) descriptions = new LinkedHashMap<>();
    }

    /**
     * The description to show for a language, or null when there is none.
     *
     * <p>Tries the full tag the caller asked for, then its primary subtag, then
     * English. {@code de-AT} therefore finds a {@code de} description, which is
     * the point: a tenant writes one German description, not one per region.
     *
     * <p>Matching is case-insensitive because language tags are, and browsers
     * are inconsistent about it.
     */
    public String describe(String languageTag) {
        if (descriptions == null || descriptions.isEmpty()) return null;

        Map<String, String> byLower = new LinkedHashMap<>();
        descriptions.forEach((k, v) -> {
            if (k != null && v != null && !v.isBlank()) {
                byLower.put(k.toLowerCase(Locale.ROOT), v);
            }
        });

        if (languageTag != null && !languageTag.isBlank()) {
            String tag = languageTag.trim().toLowerCase(Locale.ROOT);
            String exact = byLower.get(tag);
            if (exact != null) return exact;

            int dash = tag.indexOf('-');
            if (dash > 0) {
                String primary = byLower.get(tag.substring(0, dash));
                if (primary != null) return primary;
            }
        }
        return byLower.get("en");
    }
}
