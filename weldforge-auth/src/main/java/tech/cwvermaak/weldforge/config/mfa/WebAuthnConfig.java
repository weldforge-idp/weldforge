package tech.cwvermaak.weldforge.config.mfa;

import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import tech.cwvermaak.weldforge.service.mfa.WebAuthnCredentialRepository;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * WebAuthn relying-party wiring. A single RP is configured per deployment —
 * the RP id is the domain the browser sees, and cross-tenant isolation is
 * enforced at the user/credential lookup layer, not at the RP layer.
 */
@Configuration
public class WebAuthnConfig {

    @Value("${app.mfa.webauthn.rp-id:localhost}")
    private String rpId;

    @Value("${app.mfa.webauthn.rp-name:WeldForge}")
    private String rpName;

    @Value("${app.mfa.webauthn.origins:http://localhost:4200,http://localhost:8076}")
    private String originsCsv;

    @Bean
    public RelyingParty webAuthnRelyingParty(WebAuthnCredentialRepository credentialRepository) {
        Set<String> origins = new LinkedHashSet<>(Arrays.asList(originsCsv.split("\\s*,\\s*")));
        RelyingPartyIdentity identity = RelyingPartyIdentity.builder()
                .id(rpId)
                .name(rpName)
                .build();
        return RelyingParty.builder()
                .identity(identity)
                .credentialRepository(credentialRepository)
                .origins(origins)
                .allowOriginPort(true)
                .build();
    }
}
