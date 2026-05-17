package tech.cwvermaak.weldforge.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Entity
@Table(name = "tenants")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Tenant {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 64)
    private String slug;

    @Column(nullable = false)
    private String name;

    @Column(name = "display_name")
    private String displayName;

    @Column(nullable = false)
    @Builder.Default
    private Boolean enabled = true;

    /** Self-service registration on the login page. */
    @Column(name = "registration_enabled", nullable = false)
    @Builder.Default
    private Boolean registrationEnabled = true;

    /** "Forgot your password?" link on the login page. */
    @Column(name = "password_recovery_enabled", nullable = false)
    @Builder.Default
    private Boolean passwordRecoveryEnabled = true;

    /** Require email verification before a self-registered user can sign in. */
    @Column(name = "email_verification_required", nullable = false)
    @Builder.Default
    private Boolean emailVerificationRequired = true;

    /**
     * Free-form per-tenant branding payload (JSONB), consumed by the Angular
     * admin-portal auth screens — {@code login.component.ts} /
     * {@code auth-shell.component.ts} and {@code TenantBrandingService}.
     * Three families of keys:
     * <ul>
     *   <li><b>CSS-variable keys</b> — {@code primaryColor, primaryDarkColor,
     *       accentColor, accentDarkColor, bgColor, bg2Color, bg3Color,
     *       borderColor, textColor, text2Color, text3Color, displayFont,
     *       sansFont, monoFont} — applied as {@code --wf-*} overrides on
     *       {@code :root}.</li>
     *   <li><b>Theme switch</b> — {@code theme}: {@code "light"} toggles the
     *       light Angular Material colour theme; anything else is the default
     *       dark.</li>
     *   <li><b>Content keys</b> — {@code logoUrl, wordmark, headline, eyebrow,
     *       tagline, ctaLabel, hideFooter}.</li>
     * </ul>
     *
     * <p>The canonical, exhaustive contract is {@code docs/tenant-branding.md}
     * — update it when adding a key. Unknown keys are ignored (additive
     * evolution is safe).
     *
     * <p>NOTE: the backend {@code LoginController} also reads branding, but
     * nginx serves the Angular portal at {@code /login} — {@code LoginController}
     * is shadowed and is <i>not</i> the page users see. Brand the Angular
     * surface, not {@code LoginController}.
     */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "branding", columnDefinition = "jsonb")
    private Map<String, Object> branding;

    /**
     * Per-tenant access token TTL in milliseconds. Null = use the
     * application default. PRD SSO-03: range 1 min – 30 days.
     */
    @Column(name = "access_ttl_ms")
    private Long accessTtlMs;

    /** Per-tenant refresh token TTL in milliseconds. Null = default. */
    @Column(name = "refresh_ttl_ms")
    private Long refreshTtlMs;

    /**
     * Per-tenant custom JWT claims injected into every access + ID token.
     * PRD OA2-07. Stored as JSONB.
     */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "custom_claims", columnDefinition = "jsonb")
    private Map<String, Object> customClaims;

    /**
     * Ordered list of identity-matching rules used when resolving a
     * federated identity to a local user. PRD FED-02.
     */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "matching_rules", columnDefinition = "jsonb")
    private List<Map<String, Object>> matchingRules;

    /**
     * Ordered list of JSONPath-based claim transformation rules.
     * PRD FED-04.
     */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "claim_transforms", columnDefinition = "jsonb")
    private List<Map<String, Object>> claimTransforms;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @PrePersist
    void onCreate() {
        LocalDateTime now = LocalDateTime.now();
        if (createdAt == null) createdAt = now;
        updatedAt = now;
        if (enabled == null) enabled = true;
        if (registrationEnabled == null) registrationEnabled = true;
        if (passwordRecoveryEnabled == null) passwordRecoveryEnabled = true;
        if (emailVerificationRequired == null) emailVerificationRequired = true;
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
