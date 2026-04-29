package tech.cwvermaak.intellisso.service.pki;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.intellisso.model.IssuedCertificate;
import tech.cwvermaak.intellisso.model.TenantCertificateAuthority;
import tech.cwvermaak.intellisso.repository.TenantCertificateAuthorityRepository;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Optional;

/**
 * RFC 6960 OCSP responder (PRD X50-05). Accepts a DER-encoded OCSPReq
 * and returns a signed BasicOCSPResp carrying the status of each
 * certificate ID in the request.
 *
 * <p>This is a minimal nonce-less implementation — sufficient for relying
 * parties that poll for status, and the full OCSP state machine (nonces,
 * archive cutoffs) can be bolted on later without schema changes.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class OcspResponderService {

    private final TenantCertificateAuthorityRepository caRepository;
    private final CertificateAuthorityService certificateAuthorityService;

    @Transactional(readOnly = true)
    public byte[] respond(Long tenantId, byte[] requestBytes) {
        try {
            TenantCertificateAuthority ca = caRepository.findByTenantId(tenantId)
                    .orElseThrow(() -> new EntityNotFoundException("Tenant has no CA"));
            X509Certificate caCert = PemUtils.readCertificate(ca.getCertificatePem());
            PrivateKey caKey = PemUtils.readPrivateKey(ca.getPrivateKeyPem());

            OCSPReq request = new OCSPReq(requestBytes);
            DigestCalculatorProvider digestProvider = new JcaDigestCalculatorProviderBuilder().build();
            BasicOCSPRespBuilder basicBuilder = new JcaBasicOCSPRespBuilder(
                    caCert.getPublicKey(), digestProvider.get(CertificateID.HASH_SHA1));

            for (Req req : request.getRequestList()) {
                CertificateID certId = req.getCertID();
                BigInteger serial = certId.getSerialNumber();
                CertificateStatus status = statusFor(serial);
                basicBuilder.addResponse(certId, status);
            }

            ContentSigner signer = new JcaContentSignerBuilder(ca.getSignatureAlgorithm()).build(caKey);
            X509CertificateHolder[] chain = {new X509CertificateHolder(caCert.getEncoded())};
            BasicOCSPResp basicResp = basicBuilder.build(signer, chain, new Date());

            OCSPRespBuilder responseBuilder = new OCSPRespBuilder();
            OCSPResp resp = responseBuilder.build(OCSPResponseStatus.SUCCESSFUL, basicResp);
            return resp.getEncoded();
        } catch (Exception e) {
            log.warn("OCSP respond failed: {}", e.getMessage());
            try {
                return new OCSPRespBuilder()
                        .build(OCSPResponseStatus.INTERNAL_ERROR, null)
                        .getEncoded();
            } catch (Exception nested) {
                throw new IllegalStateException("Failed to build OCSP error response", nested);
            }
        }
    }

    private CertificateStatus statusFor(BigInteger serial) {
        Optional<IssuedCertificate> match = certificateAuthorityService.findBySerial(serial.toString(16));
        if (match.isEmpty()) {
            // Per RFC 6960, "unknown" is distinct from "good"; we have
            // no record of this serial, so the relying party should
            // treat it with suspicion.
            return new org.bouncycastle.cert.ocsp.UnknownStatus();
        }
        IssuedCertificate cert = match.get();
        if (cert.getStatus() == IssuedCertificate.Status.REVOKED) {
            Date when = cert.getRevokedAt() != null
                    ? Date.from(cert.getRevokedAt().atZone(java.time.ZoneId.systemDefault()).toInstant())
                    : new Date();
            return new RevokedStatus(when, mapReason(cert.getRevocationReason()));
        }
        return CertificateStatus.GOOD;
    }

    private static int mapReason(IssuedCertificate.RevocationReason r) {
        if (r == null) return 0; // unspecified
        return switch (r) {
            case KEY_COMPROMISE -> 1;
            case CA_COMPROMISE -> 2;
            case AFFILIATION_CHANGED -> 3;
            case SUPERSEDED -> 4;
            case CESSATION_OF_OPERATION -> 5;
            case CERTIFICATE_HOLD -> 6;
            case PRIVILEGE_WITHDRAWN -> 9;
            default -> 0;
        };
    }
}
