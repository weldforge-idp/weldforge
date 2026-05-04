package tech.cwvermaak.weldforge.service.pki;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.weldforge.model.IssuedCertificate;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;

import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.util.Optional;

/**
 * PRD X50-03. Resolves a presented X.509 client certificate to a local
 * {@link User}.
 *
 * <p>Validation policy:
 * <ol>
 *   <li>Fingerprint the cert (SHA-256 of the DER encoding).</li>
 *   <li>Look up the fingerprint in {@code issued_certificates}. A missing
 *       row means the cert was not issued by this CA and is rejected.</li>
 *   <li>Reject anything that is not {@code ACTIVE} or whose
 *       {@code notAfter} is in the past.</li>
 *   <li>Verify the presented cert's signature against the stored
 *       certificate's public key as a final sanity check — it rules out
 *       a tampered copy even if the fingerprint somehow collided.</li>
 * </ol>
 *
 * <p>Callers plug this into any protocol that can carry a client cert:
 * the SSL terminator (via {@code javax.servlet.request.X509Certificate}),
 * direct TLS termination, or an admin-facing "import cert + login"
 * endpoint.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ClientCertificateAuthenticator {

    public record Result(boolean success, Tenant tenant, User user, String reason) {}

    private final CertificateAuthorityService certificateAuthorityService;

    @Transactional(readOnly = true)
    public Result authenticate(X509Certificate presented) {
        if (presented == null) return fail("no certificate presented");
        try {
            String fingerprint = CertificateAuthorityService.sha256Fingerprint(presented);
            Optional<IssuedCertificate> match = certificateAuthorityService.findByFingerprint(fingerprint);
            if (match.isEmpty()) return fail("certificate not issued by any tenant CA");

            IssuedCertificate stored = match.get();
            if (stored.getStatus() != IssuedCertificate.Status.ACTIVE) {
                return fail("certificate status is " + stored.getStatus());
            }
            if (stored.getExpiresAt() != null && stored.getExpiresAt().isBefore(LocalDateTime.now())) {
                return fail("certificate expired at " + stored.getExpiresAt());
            }

            // Sanity-check the presented cert against the stored PEM.
            X509Certificate storedCert = PemUtils.readCertificate(stored.getCertificatePem());
            if (!java.util.Arrays.equals(storedCert.getEncoded(), presented.getEncoded())) {
                return fail("presented certificate differs from stored copy");
            }

            User user = stored.getUser();
            if (user == null) {
                return fail("certificate is not bound to any user");
            }
            if (!user.isActive()) {
                return fail("user is inactive");
            }
            return new Result(true, user.getTenant(), user, null);
        } catch (Exception e) {
            log.debug("Client cert auth failed: {}", e.getMessage());
            return fail("verification failed: " + e.getMessage());
        }
    }

    private static Result fail(String reason) {
        return new Result(false, null, null, reason);
    }
}
