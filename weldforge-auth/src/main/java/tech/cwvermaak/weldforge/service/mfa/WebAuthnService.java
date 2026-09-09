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

import tech.cwvermaak.weldforge.model.WebAuthnCeremony;
import tech.cwvermaak.weldforge.repository.WebAuthnCeremonyRepository;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Optional;

/**
 * WebAuthn/FIDO2 registration and authentication ceremonies.
 *
 * <p>Ceremony state — the random challenge plus the bound user and credential
 * ids — is persisted in {@code webauthn_ceremony}, keyed by the challenge token
 * returned to the client (CONF-3.1). It used to live in two
 * {@code ConcurrentHashMap}s on whichever instance served the first request,
 * which failed across a rolling update (two pods exist during every deploy) and
 * was the only piece of in-process state preventing a second replica.
 *
 * <p>Ceremonies are <b>single-use and time-bounded</b>. The finish step deletes
 * the row before verifying, so a replayed response finds nothing, and an
 * abandoned ceremony expires rather than leaking — closing the tab at the
 * browser's prompt is normal behaviour, and the maps never evicted those.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class WebAuthnService {

    /** How long a started ceremony stays redeemable. Matches the MFA challenge TTL. */
    private static final long CEREMONY_TTL_SECONDS = 300;

    private final RelyingParty relyingParty;
    private final MfaFactorRepository mfaFactorRepository;
    private final AuditService auditService;
    private final io.micrometer.core.instrument.MeterRegistry meterRegistry;
    private final WebAuthnCeremonyRepository ceremonyRepository;
    private final ObjectMapper objectMapper = new ObjectMapper();

    // ---- Registration ------------------------------------------------

    /** Start a WebAuthn registration ceremony for an authenticated user. */
    @Transactional
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
        try {
            // The library's own JSON is stored verbatim rather than rebuilt from
            // parsed fields: a semantic difference between what was issued and
            // what is verified is exactly what a challenge exists to prevent.
            persistCeremony(user, challengeToken, WebAuthnCeremony.Type.REGISTRATION, creation.toJson());
            return creation.toCredentialsCreateJson();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to serialise registration options", e);
        }
    }

    /** Finish a WebAuthn registration ceremony and persist the credential. */
    @Transactional
    public MfaFactor finishRegistration(User user, String challengeToken, String publicKeyCredentialJson, String label)
            throws RegistrationFailedException, IOException {
        PublicKeyCredentialCreationOptions request = consume(
                challengeToken, user, WebAuthnCeremony.Type.REGISTRATION,
                json -> {
                    try {
                        return PublicKeyCredentialCreationOptions.fromJson(json);
                    } catch (IOException e) {
                        throw new IllegalStateException("Corrupt WebAuthn registration ceremony", e);
                    }
                });
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

    @Transactional
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
        try {
            persistCeremony(user, challengeToken, WebAuthnCeremony.Type.ASSERTION, request.toJson());
            return request.toCredentialsGetJson();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to serialise assertion options", e);
        }
    }

    @Transactional
    public boolean finishAssertion(User user, String challengeToken, String publicKeyCredentialJson)
            throws AssertionFailedException, IOException {
        AssertionRequest request = consume(
                challengeToken, user, WebAuthnCeremony.Type.ASSERTION,
                json -> {
                    try {
                        return AssertionRequest.fromJson(json);
                    } catch (IOException e) {
                        throw new IllegalStateException("Corrupt WebAuthn assertion ceremony", e);
                    }
                });
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

    // ---- Ceremony persistence (CONF-3.1) ------------------------------

    /**
     * Persist a started ceremony so any replica can complete it.
     *
     * <p>Deliberately NOT annotated {@code @Transactional}: it is called from
     * {@code startRegistration} / {@code startAssertion} on this same bean, and
     * a self-invocation bypasses the Spring proxy, so the annotation would be
     * silently ignored -- the trap already documented on
     * {@code RefreshTokenFamilyRevoker}. The transaction is declared on the
     * public entry points instead, where the proxy can see it.
     */
    private void persistCeremony(User user, String challengeToken,
                                 WebAuthnCeremony.Type type, String optionsJson) {
        ceremonyRepository.save(WebAuthnCeremony.builder()
                .challengeToken(challengeToken)
                .userId(user.getId())
                .ceremonyType(type)
                .optionsJson(optionsJson)
                .createdAt(LocalDateTime.now())
                .expiresAt(LocalDateTime.now().plusSeconds(CEREMONY_TTL_SECONDS))
                .build());
    }

    /**
     * Take a started ceremony, or return null when there is nothing valid to take.
     *
     * <p>Deletes before returning, so the ceremony is single-use: a replayed
     * response finds nothing, exactly as the removing {@code map.remove} it
     * replaces did.
     *
     * <p>Three things make a row unusable, and all three return null rather than
     * throwing, because the caller's "unknown or expired challenge" is the
     * honest answer to every one of them:
     * <ul>
     *   <li><b>Expired</b> — a ceremony older than its TTL. The row is dropped
     *       on the way past so it does not wait for the prune job.</li>
     *   <li><b>Wrong user</b> — a challenge token cannot be redeemed against a
     *       different account, even by someone who legitimately holds it.</li>
     *   <li><b>Wrong type</b> — an assertion token cannot finish a registration.
     *       They share a table, so nothing else stops the confusion.</li>
     * </ul>
     */
    private <T> T consume(String challengeToken, User user, WebAuthnCeremony.Type expectedType,
                          java.util.function.Function<String, T> parser) {
        if (challengeToken == null || challengeToken.isBlank()) return null;

        Optional<WebAuthnCeremony> found = ceremonyRepository.findById(challengeToken);
        if (found.isEmpty()) return null;
        WebAuthnCeremony row = found.get();

        // Delete first: the ceremony is spent by the attempt, not by its success.
        ceremonyRepository.delete(row);

        if (row.getExpiresAt().isBefore(LocalDateTime.now())) return null;
        if (!row.getUserId().equals(user.getId())) {
            log.warn("WebAuthn ceremony redeemed by the wrong user: started_for={} presented_by={}",
                    row.getUserId(), user.getId());
            return null;
        }
        if (row.getCeremonyType() != expectedType) {
            log.warn("WebAuthn ceremony type mismatch: stored={} expected={}",
                    row.getCeremonyType(), expectedType);
            return null;
        }
        return parser.apply(row.getOptionsJson());
    }
}
