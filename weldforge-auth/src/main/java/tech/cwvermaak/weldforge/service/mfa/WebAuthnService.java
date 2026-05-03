package tech.cwvermaak.weldforge.service.mfa;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.webauthn.*;
import com.yubico.webauthn.data.*;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.weldforge.model.MfaFactor;
import tech.cwvermaak.weldforge.model.MfaFactorType;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.MfaFactorRepository;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * WebAuthn/FIDO2 registration and authentication ceremonies. The ceremony
 * state (the random challenge + bound user/credential ids) lives in an
 * in-memory map keyed by the challenge token we return to the client.
 *
 * In a multi-instance deployment this store should be swapped for Redis or
 * the DB — it is fine for single-node dev and staging, and the rest of the
 * auth pipeline is stateless.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class WebAuthnService {

    private final RelyingParty relyingParty;
    private final MfaFactorRepository mfaFactorRepository;
    private final ObjectMapper objectMapper = new ObjectMapper();

    private final ConcurrentMap<String, PublicKeyCredentialCreationOptions> pendingRegistrations = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, AssertionRequest>                    pendingAssertions   = new ConcurrentHashMap<>();

    // ---- Registration ------------------------------------------------

    /** Start a WebAuthn registration ceremony for an authenticated user. */
    public String startRegistration(User user, String challengeToken) {
        UserIdentity userIdentity = UserIdentity.builder()
                .name(user.getEmail())
                .displayName(user.getName() != null ? user.getName() : user.getEmail())
                .id(WebAuthnCredentialRepository.userHandle(user.getId()))
                .build();

        StartRegistrationOptions opts = StartRegistrationOptions.builder()
                .user(userIdentity)
                .authenticatorSelection(AuthenticatorSelectionCriteria.builder()
                        .userVerification(UserVerificationRequirement.PREFERRED)
                        .build())
                .build();

        PublicKeyCredentialCreationOptions creation = relyingParty.startRegistration(opts);
        pendingRegistrations.put(challengeToken, creation);
        try {
            return creation.toCredentialsCreateJson();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to serialise registration options", e);
        }
    }

    /** Finish a WebAuthn registration ceremony and persist the credential. */
    @Transactional
    public MfaFactor finishRegistration(User user, String challengeToken, String publicKeyCredentialJson, String label)
            throws RegistrationFailedException, IOException {
        PublicKeyCredentialCreationOptions request = pendingRegistrations.remove(challengeToken);
        if (request == null) {
            throw new IllegalStateException("Unknown or expired WebAuthn registration challenge");
        }

        PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> pkc =
                PublicKeyCredential.parseRegistrationResponseJson(publicKeyCredentialJson);

        RegistrationResult result = relyingParty.finishRegistration(
                FinishRegistrationOptions.builder()
                        .request(request)
                        .response(pkc)
                        .build());

        MfaFactor factor = MfaFactor.builder()
                .user(user)
                .type(MfaFactorType.WEBAUTHN)
                .label(label != null ? label : "Security key")
                .credentialId(result.getKeyId().getId().getBase64Url())
                .publicKeyCose(result.getPublicKeyCose().getBase64Url())
                .signatureCount(result.getSignatureCount())
                .aaguid(result.getAaguid() != null ? result.getAaguid().getHex() : null)
                .userHandle(WebAuthnCredentialRepository.userHandle(user.getId()).getBase64Url())
                .enabled(true)
                .verified(true)
                .build();
        return mfaFactorRepository.save(factor);
    }

    // ---- Assertion (login) ------------------------------------------

    public String startAssertion(User user, String challengeToken) {
        AssertionRequest request = relyingParty.startAssertion(StartAssertionOptions.builder()
                .username(user.getEmail())
                .userVerification(UserVerificationRequirement.PREFERRED)
                .build());
        pendingAssertions.put(challengeToken, request);
        try {
            return request.toCredentialsGetJson();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to serialise assertion options", e);
        }
    }

    @Transactional
    public boolean finishAssertion(User user, String challengeToken, String publicKeyCredentialJson)
            throws AssertionFailedException, IOException {
        AssertionRequest request = pendingAssertions.remove(challengeToken);
        if (request == null) return false;

        PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> pkc =
                PublicKeyCredential.parseAssertionResponseJson(publicKeyCredentialJson);

        AssertionResult result = relyingParty.finishAssertion(FinishAssertionOptions.builder()
                .request(request)
                .response(pkc)
                .build());

        if (!result.isSuccess()) return false;

        // Bump the signature counter and last-used timestamp on the row.
        Optional<MfaFactor> row = mfaFactorRepository.findByCredentialId(result.getCredential().getCredentialId().getBase64Url());
        row.ifPresent(f -> {
            if (f.getUser() == null || !f.getUser().getId().equals(user.getId())) {
                throw new IllegalStateException("WebAuthn credential belongs to a different user");
            }
            f.setSignatureCount(result.getSignatureCount());
            f.setLastUsedAt(LocalDateTime.now());
            mfaFactorRepository.save(f);
        });
        return true;
    }
}
