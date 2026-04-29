package tech.cwvermaak.intellisso.service.pki;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.intellisso.config.tenant.TenantAccessor;
import tech.cwvermaak.intellisso.model.IssuedCertificate;
import tech.cwvermaak.intellisso.model.Tenant;
import tech.cwvermaak.intellisso.model.TenantCertificateAuthority;
import tech.cwvermaak.intellisso.model.User;
import tech.cwvermaak.intellisso.model.dto.CertificateAuthorityDto;
import tech.cwvermaak.intellisso.model.dto.IssuedCertificateDto;
import tech.cwvermaak.intellisso.repository.IssuedCertificateRepository;
import tech.cwvermaak.intellisso.repository.TenantCertificateAuthorityRepository;
import tech.cwvermaak.intellisso.repository.TenantRepository;
import tech.cwvermaak.intellisso.repository.UserRepository;
import tech.cwvermaak.intellisso.service.audit.AuditEventTypes;
import tech.cwvermaak.intellisso.service.audit.AuditService;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

/**
 * Implements the core PKI operations for PRD §3.6:
 *
 * <ul>
 *   <li>{@code X50-01} — create a per-tenant root CA and issue X.509 v3
 *       end-entity certificates.</li>
 *   <li>{@code X50-02} — revoke certificates and generate signed CRLs.</li>
 *   <li>{@code X50-03} — lookup by fingerprint so the client-cert
 *       authentication filter can resolve a presented cert to a user.</li>
 *   <li>{@code X50-04} — expose queries for the renewal scheduler.</li>
 *   <li>{@code X50-05} — query status for OCSP responses.</li>
 * </ul>
 *
 * <p>Everything is tenant-scoped through {@link TenantAccessor}; the CA's
 * private key is encrypted at rest via {@link TenantCertificateAuthority}'s
 * {@code @Convert} column.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CertificateAuthorityService {

    private static final SecureRandom RNG = new SecureRandom();

    private final TenantAccessor tenantAccessor;
    private final TenantRepository tenantRepository;
    private final UserRepository userRepository;
    private final TenantCertificateAuthorityRepository caRepository;
    private final IssuedCertificateRepository certRepository;
    private final AuditService auditService;

    // ---- CA lifecycle ---------------------------------------------

    /**
     * Generate a new root CA for the current tenant. RSA-4096 by default;
     * valid for {@code yearsValid} years (default 10 if null).
     */
    @Transactional
    public CertificateAuthorityDto createRootCa(Integer yearsValid) {
        tenantAccessor.requireTenantAdmin();
        Tenant tenant = tenantAccessor.requireTenant();
        if (caRepository.findByTenantId(tenant.getId()).isPresent()) {
            throw new IllegalStateException("Tenant already has a root CA");
        }
        int years = yearsValid == null ? 10 : yearsValid;
        KeyPair keyPair = generateRsaKeyPair(4096);

        String cn = "WeldForge Root CA (" + tenant.getSlug() + ")";
        X500Name subject = new X500Name("CN=" + cn + ",O=WeldForge,OU=" + tenant.getSlug());
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime expires = now.plusYears(years);

        X509Certificate cert = buildSelfSignedCa(
                subject, keyPair, now, expires);

        TenantCertificateAuthority ca = TenantCertificateAuthority.builder()
                .tenant(tenant)
                .subjectDn(subject.toString())
                .certificatePem(PemUtils.writeCertificate(cert))
                .privateKeyPem(PemUtils.writePrivateKey(keyPair.getPrivate()))
                .keyAlgorithm("RSA")
                .keySize(4096)
                .signatureAlgorithm("SHA256withRSA")
                .crlNumber(1)
                .createdAt(now)
                .expiresAt(expires)
                .build();
        caRepository.save(ca);

        auditService.recordAdmin(AuditEventTypes.PKI_CA_CREATE, null,
                AuditEventTypes.TARGET_CERTIFICATE_AUTHORITY, String.valueOf(ca.getId()),
                AuditService.meta("subject", subject.toString(), "years_valid", years));

        return toDto(ca);
    }

    @Transactional(readOnly = true)
    public CertificateAuthorityDto getCa() {
        tenantAccessor.requireAnyAdmin();
        return toDto(loadCa());
    }

    /** Public-safe: used by the CRL endpoint to return the CA cert PEM. */
    @Transactional(readOnly = true)
    public String getCaCertificatePem(Long tenantId) {
        return caRepository.findByTenantId(tenantId)
                .map(TenantCertificateAuthority::getCertificatePem)
                .orElseThrow(() -> new EntityNotFoundException("Tenant has no CA"));
    }

    // ---- End-entity certs -----------------------------------------

    /**
     * Issue an end-entity certificate signed by the tenant's root CA.
     * Returns the cert PEM and the freshly-generated private key PEM —
     * this is the only moment the private key is visible to the caller;
     * it is never stored.
     */
    @Transactional
    public IssuedCertificateDto issueCertificate(IssuedCertificateDto dto) {
        tenantAccessor.requireTenantAdmin();
        TenantCertificateAuthority ca = loadCa();
        if (dto.getSubjectDn() == null || dto.getSubjectDn().isBlank()) {
            throw new IllegalArgumentException("subjectDn is required");
        }
        int days = dto.getValidityDays() == null ? 365 : dto.getValidityDays();

        KeyPair keyPair = generateRsaKeyPair(2048);

        BigInteger serial = new BigInteger(128, RNG);
        LocalDateTime notBefore = LocalDateTime.now();
        LocalDateTime notAfter = notBefore.plusDays(days);

        X500Name subject = new X500Name(dto.getSubjectDn());
        X500Name issuer = new X500Name(ca.getSubjectDn());
        PrivateKey caKey = PemUtils.readPrivateKey(ca.getPrivateKeyPem());

        X509Certificate cert = buildEndEntity(
                issuer, caKey, subject, keyPair.getPublic(), serial,
                toDate(notBefore), toDate(notAfter),
                dto.getSans() == null ? List.of() : dto.getSans());

        String pem = PemUtils.writeCertificate(cert);
        String keyPem = PemUtils.writePrivateKey(keyPair.getPrivate());
        String fingerprint = sha256Fingerprint(cert);

        User user = dto.getUserId() == null ? null :
                userRepository.findByIdAndTenantId(dto.getUserId(), ca.getTenant().getId()).orElse(null);

        IssuedCertificate issued = IssuedCertificate.builder()
                .tenant(ca.getTenant())
                .ca(ca)
                .serialNumber(serial.toString(16))
                .subjectDn(dto.getSubjectDn())
                .sans(dto.getSans() == null ? null : String.join(",", dto.getSans()))
                .certificatePem(pem)
                .fingerprintSha256(fingerprint)
                .status(IssuedCertificate.Status.ACTIVE)
                .issuedAt(notBefore)
                .expiresAt(notAfter)
                .user(user)
                .build();
        certRepository.save(issued);

        auditService.recordAdmin(AuditEventTypes.PKI_CERT_ISSUE, null,
                AuditEventTypes.TARGET_ISSUED_CERTIFICATE, issued.getSerialNumber(),
                AuditService.meta("subject", dto.getSubjectDn(), "days", days,
                        "fingerprint_sha256", fingerprint));

        IssuedCertificateDto out = toDto(issued);
        out.setPrivateKeyPem(keyPem); // single-reveal, matches API-key pattern
        return out;
    }

    @Transactional(readOnly = true)
    public List<IssuedCertificateDto> listCertificates() {
        tenantAccessor.requireAnyAdmin();
        Long tid = tenantAccessor.requireTenantId();
        return certRepository.findByTenantId(tid).stream()
                .map(CertificateAuthorityService::toDto)
                .toList();
    }

    @Transactional
    public void revokeCertificate(String serial, IssuedCertificate.RevocationReason reason) {
        tenantAccessor.requireTenantAdmin();
        Long tid = tenantAccessor.requireTenantId();
        IssuedCertificate cert = certRepository.findByTenantIdAndSerialNumber(tid, serial)
                .orElseThrow(() -> new EntityNotFoundException("Certificate " + serial + " not found"));
        if (cert.getStatus() == IssuedCertificate.Status.REVOKED) return;
        cert.setStatus(IssuedCertificate.Status.REVOKED);
        cert.setRevocationReason(reason == null ? IssuedCertificate.RevocationReason.UNSPECIFIED : reason);
        cert.setRevokedAt(LocalDateTime.now());

        // Bump CRL number so the next generated CRL supersedes any
        // previously published list (RFC 5280 §5.2.3).
        TenantCertificateAuthority ca = cert.getCa();
        ca.setCrlNumber(ca.getCrlNumber() + 1);

        auditService.recordAdmin(AuditEventTypes.PKI_CERT_REVOKE, null,
                AuditEventTypes.TARGET_ISSUED_CERTIFICATE, serial,
                AuditService.meta("reason", cert.getRevocationReason().name()));
    }

    // ---- CRL ------------------------------------------------------

    /**
     * Generate a freshly-signed CRL for the tenant. Valid for 24 hours
     * (next update). Returned as PEM. PRD X50-02.
     */
    @Transactional(readOnly = true)
    public String generateCrlPem(Long tenantId) {
        TenantCertificateAuthority ca = caRepository.findByTenantId(tenantId)
                .orElseThrow(() -> new EntityNotFoundException("Tenant has no CA"));
        try {
            X509Certificate caCert = PemUtils.readCertificate(ca.getCertificatePem());
            PrivateKey caKey = PemUtils.readPrivateKey(ca.getPrivateKeyPem());

            Date now = new Date();
            Date nextUpdate = new Date(now.getTime() + 24L * 60 * 60 * 1000);

            JcaX509v2CRLBuilder builder = new JcaX509v2CRLBuilder(caCert, now);
            builder.setNextUpdate(nextUpdate);

            for (IssuedCertificate c : certRepository.findByTenantIdAndStatus(
                    tenantId, IssuedCertificate.Status.REVOKED)) {
                BigInteger serial = new BigInteger(c.getSerialNumber(), 16);
                int reason = mapReason(c.getRevocationReason());
                Date revokedAt = toDate(c.getRevokedAt());
                builder.addCRLEntry(serial, revokedAt, reason);
            }

            builder.addExtension(Extension.cRLNumber, false,
                    new org.bouncycastle.asn1.x509.CRLNumber(BigInteger.valueOf(ca.getCrlNumber())));

            ContentSigner signer = new JcaContentSignerBuilder(ca.getSignatureAlgorithm()).build(caKey);
            X509CRL crl = new org.bouncycastle.cert.jcajce.JcaX509CRLConverter()
                    .getCRL(builder.build(signer));
            return PemUtils.writeCrl(crl.getEncoded());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build CRL: " + e.getMessage(), e);
        }
    }

    // ---- Lookup helpers -------------------------------------------

    @Transactional(readOnly = true)
    public Optional<IssuedCertificate> findByFingerprint(String fingerprint) {
        return certRepository.findByFingerprintSha256(fingerprint);
    }

    @Transactional(readOnly = true)
    public Optional<IssuedCertificate> findBySerial(String serial) {
        return certRepository.findBySerialNumber(serial);
    }

    // ---- Internals -------------------------------------------------

    private TenantCertificateAuthority loadCa() {
        Long tid = tenantAccessor.requireTenantId();
        return caRepository.findByTenantId(tid)
                .orElseThrow(() -> new EntityNotFoundException("Tenant has no CA — run createRootCa first"));
    }

    private static KeyPair generateRsaKeyPair(int size) {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(size, RNG);
            return gen.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("RSA key generation failed", e);
        }
    }

    private static X509Certificate buildSelfSignedCa(X500Name subject, KeyPair keyPair,
                                                     LocalDateTime notBefore, LocalDateTime notAfter) {
        try {
            BigInteger serial = new BigInteger(128, RNG);
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    subject, serial, toDate(notBefore), toDate(notAfter), subject, keyPair.getPublic());

            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
            builder.addExtension(Extension.keyUsage, true,
                    new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.digitalSignature));
            builder.addExtension(Extension.subjectKeyIdentifier, false,
                    extUtils.createSubjectKeyIdentifier(keyPair.getPublic()));
            builder.addExtension(Extension.authorityKeyIdentifier, false,
                    extUtils.createAuthorityKeyIdentifier(keyPair.getPublic()));

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
            return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
        } catch (Exception e) {
            throw new IllegalStateException("CA build failed: " + e.getMessage(), e);
        }
    }

    private static X509Certificate buildEndEntity(X500Name issuer, PrivateKey caKey,
                                                  X500Name subject, PublicKey subjectPub,
                                                  BigInteger serial, Date notBefore, Date notAfter,
                                                  List<String> sans) {
        try {
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    issuer, serial, notBefore, notAfter, subject, subjectPub);

            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            builder.addExtension(Extension.keyUsage, true,
                    new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
            builder.addExtension(Extension.extendedKeyUsage, false,
                    new ExtendedKeyUsage(new KeyPurposeId[]{
                            KeyPurposeId.id_kp_clientAuth,
                            KeyPurposeId.id_kp_emailProtection}));
            builder.addExtension(Extension.subjectKeyIdentifier, false,
                    extUtils.createSubjectKeyIdentifier(subjectPub));

            if (!sans.isEmpty()) {
                GeneralName[] names = sans.stream()
                        .map(s -> new GeneralName(
                                s.contains("@") ? GeneralName.rfc822Name : GeneralName.dNSName, s))
                        .toArray(GeneralName[]::new);
                builder.addExtension(Extension.subjectAlternativeName, false,
                        new DERSequence((ASN1Encodable[]) names));
            }

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(caKey);
            return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
        } catch (Exception e) {
            throw new IllegalStateException("End-entity build failed: " + e.getMessage(), e);
        }
    }

    private static int mapReason(IssuedCertificate.RevocationReason r) {
        if (r == null) return CRLReason.unspecified;
        return switch (r) {
            case KEY_COMPROMISE -> CRLReason.keyCompromise;
            case CA_COMPROMISE -> CRLReason.cACompromise;
            case AFFILIATION_CHANGED -> CRLReason.affiliationChanged;
            case SUPERSEDED -> CRLReason.superseded;
            case CESSATION_OF_OPERATION -> CRLReason.cessationOfOperation;
            case CERTIFICATE_HOLD -> CRLReason.certificateHold;
            case PRIVILEGE_WITHDRAWN -> CRLReason.privilegeWithdrawn;
            default -> CRLReason.unspecified;
        };
    }

    public static String sha256Fingerprint(X509Certificate cert) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(md.digest(cert.getEncoded()));
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static Date toDate(LocalDateTime t) {
        return Date.from(t.atZone(ZoneId.systemDefault()).toInstant());
    }

    private static CertificateAuthorityDto toDto(TenantCertificateAuthority ca) {
        return CertificateAuthorityDto.builder()
                .id(ca.getId())
                .subjectDn(ca.getSubjectDn())
                .certificatePem(ca.getCertificatePem())
                .keyAlgorithm(ca.getKeyAlgorithm())
                .keySize(ca.getKeySize())
                .signatureAlgorithm(ca.getSignatureAlgorithm())
                .createdAt(ca.getCreatedAt())
                .expiresAt(ca.getExpiresAt())
                .build();
    }

    private static IssuedCertificateDto toDto(IssuedCertificate c) {
        return IssuedCertificateDto.builder()
                .id(c.getId())
                .serialNumber(c.getSerialNumber())
                .subjectDn(c.getSubjectDn())
                .sans(c.getSans() == null ? List.of() : List.of(c.getSans().split(",")))
                .certificatePem(c.getCertificatePem())
                .fingerprintSha256(c.getFingerprintSha256())
                .status(c.getStatus())
                .revocationReason(c.getRevocationReason())
                .revokedAt(c.getRevokedAt())
                .issuedAt(c.getIssuedAt())
                .expiresAt(c.getExpiresAt())
                .userId(c.getUser() != null ? c.getUser().getId() : null)
                .build();
    }
}
