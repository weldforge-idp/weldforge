package tech.cwvermaak.intellisso.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "users")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** Owning tenant — every user belongs to exactly one tenant. */
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @Column(nullable = false)
    private String username;

    @Column(nullable = false)
    private String email;

    private String cellPhoneNumber;

    private boolean emailVerified;

    private boolean cellPhoneVerified;

    private String password;

    private String name;

    private String imageUrl;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AuthProvider provider;

    @Column(name = "provider_id", nullable = false)
    private String providerId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "role_id")
    private Role role;

    @Column(name = "is_super_admin", nullable = false)
    private boolean superAdmin;

    /**
     * PRD ADM-02 admin-console RBAC role. Defaults to {@link AdminRole#NONE}
     * for regular users. Super admin assignment is gated behind the
     * existing {@link #superAdmin} boolean to preserve historical data —
     * V21 migration seeds SUPER_ADMIN where the boolean was already true.
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "admin_role", nullable = false, length = 32)
    @Builder.Default
    private AdminRole adminRole = AdminRole.NONE;

    /**
     * SCIM-style deactivation flag. False means the row exists but the
     * user cannot sign in — set by SCIM PATCH operations from upstream
     * IdPs (Okta / Workday / Entra ID) when an employee leaves the org.
     * Distinct from {@link #lockedUntil} which is a transient
     * anti-brute-force lock.
     */
    @Column(nullable = false)
    private boolean active = true;

    // --- Account lockout -------------------------------------
    @Column(name = "failed_login_attempts", nullable = false)
    private int failedLoginAttempts;

    @Column(name = "locked_until")
    private LocalDateTime lockedUntil;

    // --- Session revocation ----------------------------------
    /**
     * Monotonically increasing counter that is embedded in every access
     * token as the {@code ver} claim. Bumping this value invalidates every
     * outstanding access token for the user in one atomic operation — used
     * by "log me out of all devices" and by security responses (e.g. after
     * a password change or admin-triggered MFA reset).
     */
    @Column(name = "token_version", nullable = false)
    private int tokenVersion;

    @Column(name = "created_at")
    private LocalDateTime createdAt = LocalDateTime.now();
}
