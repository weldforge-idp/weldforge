package tech.cwvermaak.weldforge.model.dto;

import lombok.Builder;
import lombok.Data;
import tech.cwvermaak.weldforge.model.AdminRole;
import tech.cwvermaak.weldforge.model.AuthProvider;

@Data
@Builder
public class UserResponseDto {
    private Long id;
    private String name;
    private String email;
    private String imageUrl;
    private AuthProvider provider;
    /** The tenant Role's NAME, or null. Kept a string for existing callers. */
    private String role;
    /**
     * The tenant Role's id, or null.
     *
     * <p>Additive on purpose. {@link #role} has always carried the name only,
     * which is enough to display but not to edit: a client that wants to
     * change the assignment has to post a {@code roleId}, and it had no way
     * to know the current one. The admin portal's Role column silently showed
     * a dash for every user because it expected an object here and got a
     * string.
     */
    private Long roleId;
    /**
     * Every tenant role this user holds, by name, sorted.
     *
     * <p>Source of truth since V62. {@link #role} and {@link #roleId} report
     * the first of these and exist for callers written before a user could
     * hold more than one.
     */
    private java.util.List<String> roles;
    /** The same set, by id, for editing the assignment. */
    private java.util.List<Long> roleIds;

    /** PRD ADM-02: admin console role (NONE / READ_ONLY / TENANT_ADMIN / SUPER_ADMIN). */
    private AdminRole adminRole;

    /**
     * Whether this account has confirmed its email address.
     *
     * <p>Added 2026-09-20 for Safe Space. The verification endpoints
     * ({@code /api/auth/verify-email}, {@code /api/auth/resend-verification})
     * and {@code User.emailVerified} have existed since 2026-05-03, but nothing
     * ever exposed the flag — so a relying application had the machinery to
     * verify an address and no way to find out whether it had been verified.
     * That is why signup could proceed on a typo'd or invented address.
     *
     * <p>Named to match the OIDC standard claim {@code email_verified}, which
     * the ID token also now carries. Prefer the claim in a resource server: it
     * needs no round trip to the IdP, so gating does not become "ask the
     * client", which is the failure mode of trusting the front end.
     */
    private boolean emailVerified;
}
