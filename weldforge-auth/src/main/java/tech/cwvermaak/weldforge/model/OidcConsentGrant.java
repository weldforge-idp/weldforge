package tech.cwvermaak.weldforge.model;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * A user's standing consent for one OIDC client (CONF-2.3).
 *
 * <p>Without this the consent screen rendered on every authorization request
 * and no record of the decision survived it, so {@code prompt=none} could not
 * be answered and users re-consented on every login — which trains people to
 * click through the one screen that asks them to think.
 *
 * <p>Scope is part of what was consented to, not an attribute of it: agreeing
 * to {@code openid email} must not silently authorise a later request for
 * {@code openid email admin:write}. {@link #covers} is what enforces that.
 */
@Entity
@Table(name = "oidc_consent_grants")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OidcConsentGrant {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "tenant_id", nullable = false)
    private Long tenantId;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "client_id", nullable = false)
    private Long clientId;

    /** Sorted, space-separated. Sorted at write time so comparison is order-insensitive. */
    @Column(name = "scopes", nullable = false, columnDefinition = "TEXT")
    private String scopes;

    @Column(name = "granted_at", nullable = false)
    private LocalDateTime grantedAt;

    @PrePersist
    void onCreate() {
        if (grantedAt == null) grantedAt = LocalDateTime.now();
    }

    /**
     * Whether this grant already covers everything {@code requested} asks for.
     *
     * <p>A subset is enough — a client that previously got {@code openid email}
     * and now asks only for {@code openid} needs no new prompt. Anything outside
     * the stored set does, which is the whole point of keying consent by scope.
     */
    public boolean covers(List<String> requested) {
        if (requested == null || requested.isEmpty()) return true;
        Set<String> granted = Set.copyOf(Arrays.asList(scopes.trim().split("\s+")));
        return granted.containsAll(requested);
    }

    /** Canonical storage form: sorted and space-separated. */
    public static String normalise(List<String> scopes) {
        return String.join(" ", new TreeSet<>(scopes));
    }
}
