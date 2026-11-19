package tech.cwvermaak.weldforge.config.saml;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import tech.cwvermaak.weldforge.config.tenant.PublicHostProperties;
import tech.cwvermaak.weldforge.model.dto.AuthResponseDto;
import tech.cwvermaak.weldforge.service.AuthService;
import tech.cwvermaak.weldforge.service.FederatedSignInRefusedException;
import tech.cwvermaak.weldforge.service.SeatLimitExceededException;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Finishes a sign-in at a tenant's upstream SAML identity provider.
 *
 * <p>Until WF-3 (security review 2026-11-15) this provisioned the account and
 * handed the request to Spring's {@code SavedRequestAwareAuthenticationSuccessHandler}.
 * Under this deployment's stateless policy that saves nothing, so the person
 * came back from their IdP anonymous to WeldForge, and none of the gates a
 * password sign-in applies (deactivated, locked, second factor, required MFA
 * enrolment) ever ran. It is the defect {@code OAuth2LoginSuccessHandler}
 * fixed for social sign-in on 2026-10-11, and it now ends the same way:
 * {@link AuthService#issueSamlUpstreamSession} applies the gates and writes
 * the same cookies a password sign-in writes.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SamlUserProvisioningSuccessHandler implements AuthenticationSuccessHandler {

    /** Login-page error code for a tenant out of seats. */
    static final String SEAT_LIMIT = "seat_limit_exceeded";

    private final SamlUpstreamProvisioner provisioner;
    private final AuthService authService;
    private final PublicHostProperties publicHost;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        if (!(authentication.getPrincipal() instanceof Saml2AuthenticatedPrincipal principal)) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unexpected authentication type");
            return;
        }
        String registrationId = principal.getRelyingPartyRegistrationId();
        int idx = registrationId == null ? -1
                : registrationId.indexOf(DatabaseRelyingPartyRegistrationRepository.SAML_INFIX);
        if (idx <= 0) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Unrecognised provider registration");
            return;
        }
        String slug = registrationId.substring(0, idx);
        String providerKey = registrationId.substring(
                idx + DatabaseRelyingPartyRegistrationRepository.SAML_INFIX.length());

        Optional<String> email;
        try {
            email = provisioner.provision(principal, slug, providerKey);
        } catch (SeatLimitExceededException full) {
            response.sendRedirect(loginPage(slug) + "#error=" + SEAT_LIMIT);
            return;
        }
        if (email.isEmpty()) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "No account for this sign-in");
            return;
        }

        Optional<AuthResponseDto> outcome;
        try {
            outcome = authService.issueSamlUpstreamSession(slug, email.get(), providerKey, request, response);
        } catch (FederatedSignInRefusedException refused) {
            response.sendRedirect(loginPage(slug) + "#error=" + refused.getCode());
            return;
        }
        if (outcome.isEmpty()) {
            log.warn("SAML sign-in provisioned no user row: tenant={} provider={}", slug, providerKey);
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "No account for this sign-in");
            return;
        }

        AuthResponseDto result = outcome.get();
        if (result.isMfaRequired()) {
            // The IdP's word is the first factor only. The challenge rides in
            // the fragment, as for social sign-in: never sent to a server.
            String factors = result.getAvailableFactors() == null ? ""
                    : String.join(",", result.getAvailableFactors().stream().map(Object::toString).toList());
            response.sendRedirect(loginPage(slug)
                    + "#mfa=" + URLEncoder.encode(result.getMfaChallengeToken(), StandardCharsets.UTF_8)
                    + "&factors=" + URLEncoder.encode(factors, StandardCharsets.UTF_8));
            return;
        }
        response.sendRedirect(publicHost.originForTenant(slug) + "/");
    }

    private String loginPage(String slug) {
        return publicHost.originForTenant(slug) + "/login";
    }
}
