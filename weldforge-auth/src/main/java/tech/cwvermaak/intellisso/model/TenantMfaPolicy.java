package tech.cwvermaak.intellisso.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

/**
 * Per-tenant MFA enforcement policy. One row per tenant — absence of a
 * row means {@link Enforcement#OPTIONAL}.
 *
 * PRD: MFA-03 (enforcement), MFA-04 / SSO-05 (default step-up age).
 */
@Entity
@Table(name = "tenant_mfa_policies",
       uniqueConstraints = @UniqueConstraint(columnNames = "tenant_id"))
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class TenantMfaPolicy {

    public enum Enforcement {
        /** Users may enroll but are not required to. */
        OPTIONAL,
        /** Every user must enroll within the grace period or be blocked. */
        REQUIRED,
        /** Reserved for future risk-signal-driven step-up (deferred). */
        RISK_ADAPTIVE
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @OneToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tenant_id", nullable = false, unique = true)
    private Tenant tenant;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    @Builder.Default
    private Enforcement enforcement = Enforcement.OPTIONAL;

    /** Days existing users get to enroll before REQUIRED blocks login. */
    @Column(name = "grace_period_days", nullable = false)
    @Builder.Default
    private Integer gracePeriodDays = 7;

    /** Default max_authentication_age (seconds). 0 = no default step-up. */
    @Column(name = "default_stepup_max_age", nullable = false)
    @Builder.Default
    private Integer defaultStepupMaxAge = 0;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @PrePersist
    void onCreate() {
        LocalDateTime now = LocalDateTime.now();
        if (createdAt == null) createdAt = now;
        updatedAt = now;
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
