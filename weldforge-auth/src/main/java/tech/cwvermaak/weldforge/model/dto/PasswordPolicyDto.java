package tech.cwvermaak.weldforge.model.dto;

import lombok.Builder;
import lombok.Data;
import tech.cwvermaak.weldforge.service.security.EffectivePasswordPolicy;

/**
 * The password rules a tenant's users must actually satisfy — baseline plus
 * that tenant's overrides, already resolved.
 *
 * <p>Served publicly and unauthenticated from
 * {@code GET /api/auth/tenants/{slug}/password-policy} so the register and
 * reset forms can state the rules <em>before</em> the user submits. A form that
 * only reveals its rules by rejecting you is the worst case for the person
 * trying to choose a good password.
 *
 * <p>Nothing here is sensitive: these are the rules the form would have to
 * describe anyway, and an attacker learns nothing from them that a single
 * registration attempt would not reveal.
 *
 * <p>Breach screening is deliberately absent. It is deployment-wide rather than
 * per-tenant (see {@link EffectivePasswordPolicy}), and advertising whether it
 * is on tells an attacker whether breached credentials are worth trying in
 * bulk — which is the one thing in this area worth not saying out loud.
 */
@Data
@Builder
public class PasswordPolicyDto {

    private int minLength;
    private int maxLength;
    private boolean requireUppercase;
    private boolean requireLowercase;
    private boolean requireDigit;
    private boolean requireSymbol;

    public static PasswordPolicyDto from(EffectivePasswordPolicy p) {
        return PasswordPolicyDto.builder()
                .minLength(p.minLength())
                .maxLength(p.maxLength())
                .requireUppercase(p.requireUppercase())
                .requireLowercase(p.requireLowercase())
                .requireDigit(p.requireDigit())
                .requireSymbol(p.requireSymbol())
                .build();
    }
}
