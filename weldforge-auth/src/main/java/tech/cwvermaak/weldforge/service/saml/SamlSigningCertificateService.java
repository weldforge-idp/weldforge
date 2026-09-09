package tech.cwvermaak.weldforge.service.saml;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.TenantSigningKey;
import tech.cwvermaak.weldforge.repository.TenantSigningKeyRepository;
import tech.cwvermaak.weldforge.service.oidc.TenantSigningKeyService;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;

/**
 * Mints and caches the self-signed X.509 certificate that wraps a tenant's SAML
 * signing key (CONF-5.4).
 *
 * <h3>Why a certificate at all</h3>
 * SAML tooling speaks X.509. Three things in this IdP disagreed about that, and
 * each broke a different SP implementation — which is why it went unnoticed for
 * so long: whichever mismatch a given tenant hit, the other two were somebody
 * else's problem.
 *
 * <ul>
 *   <li>The XML signature carried a bare {@code <ds:KeyValue>} — a raw modulus
 *       and exponent. Verifiers that resolve the signing key from
 *       {@code KeyInfo} expecting a certificate found none.</li>
 *   <li>The published metadata advertised a {@code <ds:X509Certificate>} whose
 *       contents were a raw {@code SubjectPublicKeyInfo}, not a certificate.
 *       An SP that base64-decodes that element and parses it as X.509 — which
 *       is what the element name promises — fails outright.</li>
 *   <li>The assertion {@code Issuer} was not the metadata {@code entityID}, so
 *       an SP matching one against the other rejected valid assertions.</li>
 * </ul>
 *
 * <h3>Lazily, and once</h3>
 * The certificate is derived from a key that already exists, so it is minted on
 * first use and stored, rather than requiring a backfill over every existing
 * key. Rotation produces a new one for free, because a rotated key simply has
 * no certificate yet.
 *
 * <p>Validity deliberately outlives the key-rotation window
 * ({@code app.key-rotation.max-age-days}, 90 by default) by a wide margin: an
 * expired certificate in published metadata is an outage, and the key is
 * rotated on its own schedule long before this matters. The certificate is an
 * envelope for key distribution here, not a trust anchor — SPs pin it directly
 * out of metadata, and nothing chains to it.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SamlSigningCertificateService {

    /** Ten years. See the class javadoc: expiry here is an outage, not a control. */
    private static final long VALIDITY_DAYS = 3650;

    private static final SecureRandom RNG = new SecureRandom();

    private final TenantSigningKeyRepository signingKeyRepository;
    private final TenantSigningKeyService signingKeyService;

    /**
     * The base64 DER of the certificate for this key, as it appears inside a
     * {@code <ds:X509Certificate>} element.
     *
     * @param subject the entityID to use as the certificate subject, so the
     *                certificate names the issuer an SP will see
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public String base64Certificate(Tenant tenant, TenantSigningKey key, String subject) {
        return stripPem(certificatePem(tenant, key, subject));
    }

    /** The PEM certificate for this key, minting and storing one if absent. */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public String certificatePem(Tenant tenant, TenantSigningKey key, String subject) {
        if (key.getCertificatePem() != null && !key.getCertificatePem().isBlank()) {
            return key.getCertificatePem();
        }
        String pem = mint(key, subject);

        // Re-read inside this transaction rather than saving the caller's
        // instance: the caller may hold a detached copy, and two concurrent
        // assertions would otherwise each mint a certificate and race to
        // persist different ones for the same key.
        signingKeyRepository.findById(key.getId()).ifPresent(fresh -> {
            if (fresh.getCertificatePem() == null || fresh.getCertificatePem().isBlank()) {
                fresh.setCertificatePem(pem);
                signingKeyRepository.save(fresh);
            }
        });
        key.setCertificatePem(pem);
        log.info("Minted SAML signing certificate for tenant {} kid {}", tenant.getSlug(), key.getKid());
        return pem;
    }

    /** The parsed certificate, for use in an XML signature's KeyInfo. */
    public X509Certificate certificate(Tenant tenant, TenantSigningKey key, String subject) {
        try {
            byte[] der = Base64.getDecoder().decode(stripPem(certificatePem(tenant, key, subject)));
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
        } catch (Exception e) {
            throw new IllegalStateException("Could not load the SAML signing certificate", e);
        }
    }

    private String mint(TenantSigningKey key, String subject) {
        try {
            RSAPublicKey publicKey = signingKeyService.loadPublicKey(key);
            RSAPrivateKey privateKey = signingKeyService.loadPrivateKey(key);

            // Self-signed: subject and issuer are the same name, which is what
            // an IdP signing certificate is. The subject is the entityID so the
            // certificate names the issuer the SP sees in the assertion.
            X500Name name = new X500Name("CN=" + escapeDn(subject));
            Instant now = Instant.now();

            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    name,
                    new BigInteger(160, RNG),
                    // Backdated slightly: a verifier with a fast clock would
                    // otherwise reject a certificate minted moments earlier.
                    Date.from(now.minus(1, ChronoUnit.HOURS)),
                    Date.from(now.plus(VALIDITY_DAYS, ChronoUnit.DAYS)),
                    name,
                    publicKey);

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(privateKey);
            X509Certificate certificate = new JcaX509CertificateConverter()
                    .getCertificate(builder.build(signer));

            return "-----BEGIN CERTIFICATE-----\n"
                    + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                            .encodeToString(certificate.getEncoded())
                    + "\n-----END CERTIFICATE-----\n";
        } catch (Exception e) {
            throw new IllegalStateException("Could not mint a SAML signing certificate", e);
        }
    }

    /** Base64 DER only — no PEM armour, no line breaks. What XML-DSig wants. */
    private static String stripPem(String pem) {
        return pem.replaceAll("-----BEGIN [^-]+-----", "")
                  .replaceAll("-----END [^-]+-----", "")
                  .replaceAll("\\s", "");
    }

    /**
     * An entityID is a URL and contains characters (commas, equals signs) that
     * are separators in a Distinguished Name. Escaping them keeps the DN
     * parseable rather than silently splitting into extra RDNs.
     */
    private static String escapeDn(String value) {
        return value.replace("\\", "\\\\")
                    .replace(",", "\\,")
                    .replace("=", "\\=")
                    .replace("+", "\\+")
                    .replace("<", "\\<")
                    .replace(">", "\\>")
                    .replace(";", "\\;");
    }
}
