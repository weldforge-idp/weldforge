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
    private String role;

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
