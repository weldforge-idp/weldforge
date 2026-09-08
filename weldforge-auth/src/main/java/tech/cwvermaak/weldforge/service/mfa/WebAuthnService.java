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

import tech.cwvermaak.weldforge.service.audit.AuditEventTypes;
import tech.cwvermaak.weldforge.service.audit.AuditService;

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
    private final AuditService auditService;
    private final io.micrometer.core.instrument.MeterRegistry meterRegistry;
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

        // CONF-3.2: a credential enrolled as a SECOND factor must verify the
        // user. PREFERRED lets the authenticator silently decline, which leaves
        // the "second factor" as nothing more than possession of the key.
        // Enrolment is the right place to demand it: the user is present, and a
        // device that cannot comply fails here rather than at some later login.
        StartRegistrationOptions opts = StartRegistrationOptions.builder()
                .user(userIdentity)
                .authenticatorSelection(AuthenticatorSelectionCriteria.builder()
                        .userVerification(UserVerificationRequirement.REQUIRED)
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
                // Recorded at enrolment so the assertion ceremony can demand UV
                // for this credential without breaking grandfathered ones.
                .uvRequired(true)
                .build();
        return mfaFactorRepository.save(factor);
    }

    // ---- Assertion (login) ------------------------------------------

    public String startAssertion(User user, String challengeToken) {
        // CONF-3.2: demand user verification only when every one of this user's
        // credentials was enrolled under it. Asking REQUIRED of a credential
        // enrolled before that policy existed would lock the user out of their
        // own second factor, so grandfathered credentials keep PREFERRED and the
        // fallback is metered -- it retires itself as users re-enrol.
        UserVerificationRequirement uv = resolveUserVerification(user);
        AssertionRequest request = relyingParty.startAssertion(StartAssertionOptions.builder()
                .username(user.getEmail())
                .userVerification(uv)
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

        // CONF-3.3: a signature counter that goes backwards is the WebAuthn
        // spec's cloning signal -- two authenticators presenting the same
        // credential keep separate counters, so the lower one betrays the copy.
        // The library computes this and we were discarding it. Refuse the
        // assertion and disable the factor: this counter is the only cloning
        // evidence that ever reaches us, and it arrives exactly once.
        if (!result.isSignatureCounterValid()) {
            String credentialId = result.getCredential().getCredentialId().getBase64Url();
            Optional<MfaFactor> cloned = mfaFactorRepository.findByCredentialId(credentialId);
            log.warn("WebAuthn signature-counter regression: user_id={} credential_id={} reported={}",
                    user.getId(), credentialId, result.getSignatureCount());
            cloned.ifPresent(f -> {
                f.setEnabled(false);
                mfaFactorRepository.save(f);
            });
            auditService.recordUserAction(AuditEventTypes.MFA_WEBAUTHN_COUNTER_REGRESSION, user,
                    AuditEventTypes.TARGET_USER, String.valueOf(user.getId()),
                    AuditService.meta(
                            "credential_id", credentialId,
                            "reported_count", result.getSignatureCount(),
                            "stored_count", cloned.map(MfaFactor::getSignatureCount).orElse(null),
                            "outcome", "factor_disabled"));
            return false;
        }

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

    /**
     * The user-verification requirement for this user's assertion ceremony
     * (CONF-3.2).
     *
     * <p>{@code REQUIRED} only when every enabled WebAuthn credential the user
     * holds was enrolled under it. One grandfathered credential drops the whole
     * user back to {@code PREFERRED} -- the alternative is locking them out of a
     * factor they enrolled in good faith under the old policy.
     *
     * <p>A user with no WebAuthn credentials gets {@code REQUIRED}: there is
     * nothing to grandfather, so no reason to ask for less.
     */
    private UserVerificationRequirement resolveUserVerification(User user) {
        boolean allRequireUv = mfaFactorRepository
                .findByUserIdAndEnabledTrueAndVerifiedTrue(user.getId()).stream()
                .filter(f -> f.getType() == MfaFactorType.WEBAUTHN)
                .allMatch(MfaFactor::isUvRequired);

        if (allRequireUv) {
            return UserVerificationRequirement.REQUIRED;
        }
        meterRegistry.counter("mfa.webauthn.legacy_uv").increment();
        return UserVerificationRequirement.PREFERRED;
    }
}
