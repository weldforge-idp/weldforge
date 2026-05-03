package tech.cwvermaak.weldforge.bdd;

import io.cucumber.java.After;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import org.bouncycastle.asn1.ocsp.OCSPResponseStatus;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.springframework.security.core.context.SecurityContextHolder;
import tech.cwvermaak.weldforge.config.tenant.TenantAccessor;
import tech.cwvermaak.weldforge.config.tenant.TenantContext;
import tech.cwvermaak.weldforge.model.AdminRole;
import tech.cwvermaak.weldforge.model.IssuedCertificate;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.TenantCertificateAuthority;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.model.dto.CertificateAuthorityDto;
import tech.cwvermaak.weldforge.model.dto.IssuedCertificateDto;
import tech.cwvermaak.weldforge.repository.IssuedCertificateRepository;
import tech.cwvermaak.weldforge.repository.TenantCertificateAuthorityRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.audit.AuditService;
import tech.cwvermaak.weldforge.service.pki.CertificateAuthorityService;
import tech.cwvermaak.weldforge.service.pki.ClientCertificateAuthenticator;
import tech.cwvermaak.weldforge.service.pki.OcspResponderService;
import tech.cwvermaak.weldforge.service.pki.PemUtils;

import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Exercises the real {@link CertificateAuthorityService} and friends
 * against an in-memory JPA repo fake. The Bouncy Castle crypto path
 * runs for real — we verify the generated cert is well-formed, signed
 * by the CA, and correctly revoked via CRL + OCSP.
 */
public class EpicHPkiSteps {

    private final TestWorld world;
    private final AtomicLong ids = new AtomicLong(71000);

    private TenantCertificateAuthorityRepository caRepository;
    private IssuedCertificateRepository certRepository;
    private TenantRepository tenantRepository;
    private UserRepository userRepository;
    private TenantAccessor tenantAccessor;
    private AuditService auditService;
    private CertificateAuthorityService caService;
    private OcspResponderService ocspService;
    private ClientCertificateAuthenticator clientCertAuth;

    private final Map<Long, TenantCertificateAuthority> casByTenant = new HashMap<>();
    private final Map<String, IssuedCertificate> certsBySerial = new HashMap<>();
    private final Map<String, IssuedCertificate> certsByFingerprint = new HashMap<>();

    private CertificateAuthorityDto lastCaDto;
    private IssuedCertificateDto lastCertDto;
    private String lastCrlPem;
    private OCSPReq lastOcspReq;
    private OCSPResp lastOcspResp;
    private ClientCertificateAuthenticator.Result lastAuthResult;

    public EpicHPkiSteps(TestWorld world) {
        this.world = world;
    }

    @After
    public void clearContext() {
        TenantContext.clear();
        SecurityContextHolder.clearContext();
    }

    @SuppressWarnings("unchecked")
    private void ensureWired() {
        if (caService != null) return;

        caRepository = mock(TenantCertificateAuthorityRepository.class);
        certRepository = mock(IssuedCertificateRepository.class);
        tenantRepository = mock(TenantRepository.class);
        userRepository = mock(UserRepository.class);
        auditService = mock(AuditService.class);

        when(tenantRepository.findById(anyLong())).thenAnswer(inv -> {
            Long id = inv.getArgument(0);
            return world.tenants.values().stream()
                    .filter(t -> id.equals(t.getId())).findFirst();
        });
        when(tenantRepository.findBySlug(anyString())).thenAnswer(inv ->
                Optional.ofNullable(world.tenants.get(inv.<String>getArgument(0))));

        when(caRepository.findByTenantId(anyLong())).thenAnswer(inv ->
                Optional.ofNullable(casByTenant.get(inv.<Long>getArgument(0))));
        when(caRepository.save(any(TenantCertificateAuthority.class))).thenAnswer(inv -> {
            TenantCertificateAuthority ca = inv.getArgument(0);
            if (ca.getId() == null) ca.setId(ids.getAndIncrement());
            casByTenant.put(ca.getTenant().getId(), ca);
            return ca;
        });

        when(certRepository.save(any(IssuedCertificate.class))).thenAnswer(inv -> {
            IssuedCertificate c = inv.getArgument(0);
            if (c.getId() == null) c.setId(ids.getAndIncrement());
            certsBySerial.put(c.getSerialNumber(), c);
            certsByFingerprint.put(c.getFingerprintSha256(), c);
            return c;
        });
        when(certRepository.findBySerialNumber(anyString())).thenAnswer(inv ->
                Optional.ofNullable(certsBySerial.get(inv.<String>getArgument(0))));
        when(certRepository.findByTenantIdAndSerialNumber(anyLong(), anyString())).thenAnswer(inv -> {
            Long tid = inv.getArgument(0);
            String serial = inv.getArgument(1);
            IssuedCertificate c = certsBySerial.get(serial);
            if (c != null && c.getTenant().getId().equals(tid)) return Optional.of(c);
            return Optional.empty();
        });
        when(certRepository.findByFingerprintSha256(anyString())).thenAnswer(inv ->
                Optional.ofNullable(certsByFingerprint.get(inv.<String>getArgument(0))));
        when(certRepository.findByTenantIdAndStatus(anyLong(), any())).thenAnswer(inv -> {
            Long tid = inv.getArgument(0);
            IssuedCertificate.Status status = inv.getArgument(1);
            return certsBySerial.values().stream()
                    .filter(c -> c.getTenant().getId().equals(tid) && c.getStatus() == status)
                    .toList();
        });
        when(certRepository.findByTenantId(anyLong())).thenAnswer(inv -> {
            Long tid = inv.getArgument(0);
            return certsBySerial.values().stream()
                    .filter(c -> c.getTenant().getId().equals(tid))
                    .toList();
        });
        when(userRepository.findByIdAndTenantId(anyLong(), anyLong())).thenAnswer(inv -> {
            Long id = inv.getArgument(0);
            return world.users.values().stream()
                    .filter(u -> id.equals(u.getId())).findFirst();
        });

        tenantAccessor = new TenantAccessor(tenantRepository);
        caService = new CertificateAuthorityService(
                tenantAccessor, tenantRepository, userRepository,
                caRepository, certRepository, auditService);
        ocspService = new OcspResponderService(caRepository, caService);
        clientCertAuth = new ClientCertificateAuthenticator(caService);
    }

    private Tenant tenant(String slug) {
        return world.tenants.computeIfAbsent(slug, s ->
                Tenant.builder().id(ids.getAndIncrement()).slug(s).name(s).enabled(true).build());
    }

    // ---- Fixtures --------------------------------------------------

    @Given("tenant {string} exists for PKI tests")
    public void tenantExists(String slug) {
        ensureWired();
        tenant(slug);
    }

    @Given("the current admin acts as TENANT_ADMIN for {string}")
    public void actAsAdmin(String slug) {
        Tenant t = tenant(slug);
        TenantContext.set(t.getSlug(), t.getId(), AdminRole.TENANT_ADMIN);
    }

    @Given("user {string} exists in tenant {string} for PKI tests")
    public void userExists(String email, String slug) {
        Tenant t = tenant(slug);
        User u = User.builder()
                .id(ids.getAndIncrement())
                .tenant(t)
                .email(email)
                .username(email)
                .active(true)
                .build();
        world.users.put(slug + "|" + email.toLowerCase(), u);
    }

    // ---- CA lifecycle ---------------------------------------------

    @When("the admin creates a root CA valid for {int} years")
    public void createRootCa(int years) {
        lastCaDto = caService.createRootCa(years);
    }

    @Given("tenant {string} already has a root CA")
    public void tenantHasCa(String slug) {
        actAsAdmin(slug);
        lastCaDto = caService.createRootCa(5);
    }

    @Then("the returned CA certificate PEM is present")
    public void caPemPresent() {
        assertThat(lastCaDto).isNotNull();
        assertThat(lastCaDto.getCertificatePem()).contains("BEGIN CERTIFICATE");
    }

    @Then("the CA row is stored for tenant {string}")
    public void caStored(String slug) {
        assertThat(casByTenant.get(tenant(slug).getId())).isNotNull();
    }

    // ---- Issue ----------------------------------------------------

    @When("the admin issues a certificate with subject {string} for {int} days")
    public void issueCert(String subject, int days) {
        IssuedCertificateDto dto = IssuedCertificateDto.builder()
                .subjectDn(subject)
                .validityDays(days)
                .build();
        lastCertDto = caService.issueCertificate(dto);
    }

    @Given("the admin has issued a certificate with subject {string}")
    public void adminHasIssued(String subject) {
        issueCert(subject, 90);
    }

    @Given("the admin issues a certificate bound to user {string}")
    public void adminIssuesForUser(String email) {
        User user = world.users.get("acme|" + email.toLowerCase());
        IssuedCertificateDto dto = IssuedCertificateDto.builder()
                .subjectDn("CN=" + email)
                .validityDays(30)
                .userId(user.getId())
                .build();
        lastCertDto = caService.issueCertificate(dto);
    }

    @Then("the returned certificate PEM is present")
    public void certPemPresent() {
        assertThat(lastCertDto.getCertificatePem()).contains("BEGIN CERTIFICATE");
    }

    @Then("the returned private key PEM is present")
    public void keyPemPresent() {
        assertThat(lastCertDto.getPrivateKeyPem()).contains("BEGIN PRIVATE KEY");
    }

    @Then("the issued certificate has status {string}")
    public void certStatusIs(String expected) {
        IssuedCertificate stored = certsBySerial.get(lastCertDto.getSerialNumber());
        assertThat(stored.getStatus().name()).isEqualTo(expected);
    }

    @Then("the issued certificate is signed by the CA")
    public void certSignedByCa() throws Exception {
        X509Certificate cert = PemUtils.readCertificate(lastCertDto.getCertificatePem());
        TenantCertificateAuthority ca = casByTenant.values().iterator().next();
        X509Certificate caCert = PemUtils.readCertificate(ca.getCertificatePem());
        cert.verify(caCert.getPublicKey());
    }

    @Then("the issued certificate has EKU clientAuth")
    public void certHasClientAuth() throws Exception {
        X509Certificate cert = PemUtils.readCertificate(lastCertDto.getCertificatePem());
        byte[] ekuBytes = cert.getExtensionValue(Extension.extendedKeyUsage.getId());
        assertThat(ekuBytes).isNotNull();
        // The byte[] is DER OCTET STRING wrapping a SEQUENCE of OIDs.
        // BouncyCastle's ExtendedKeyUsage.getInstance handles unwrapping.
        org.bouncycastle.asn1.ASN1OctetString octet =
                (org.bouncycastle.asn1.ASN1OctetString) org.bouncycastle.asn1.ASN1Primitive.fromByteArray(ekuBytes);
        ExtendedKeyUsage eku = ExtendedKeyUsage.getInstance(
                org.bouncycastle.asn1.ASN1Primitive.fromByteArray(octet.getOctets()));
        assertThat(eku.hasKeyPurposeId(KeyPurposeId.id_kp_clientAuth)).isTrue();
    }

    // ---- Revocation + CRL -----------------------------------------

    @When("the admin revokes the certificate with reason {string}")
    public void revokeCert(String reason) {
        caService.revokeCertificate(lastCertDto.getSerialNumber(),
                IssuedCertificate.RevocationReason.valueOf(reason));
    }

    @Given("the admin revokes that certificate with reason {string}")
    public void givenRevoke(String reason) {
        revokeCert(reason);
    }

    @Then("the issued certificate has revocation reason {string}")
    public void revocationReasonIs(String expected) {
        IssuedCertificate stored = certsBySerial.get(lastCertDto.getSerialNumber());
        assertThat(stored.getRevocationReason().name()).isEqualTo(expected);
    }

    @When("a CRL is generated for tenant {string}")
    public void generateCrl(String slug) {
        lastCrlPem = caService.generateCrlPem(tenant(slug).getId());
    }

    @Then("the CRL is signed by the CA")
    public void crlSignedByCa() throws Exception {
        X509CRL crl = parseCrl(lastCrlPem);
        TenantCertificateAuthority ca = casByTenant.values().iterator().next();
        X509Certificate caCert = PemUtils.readCertificate(ca.getCertificatePem());
        crl.verify(caCert.getPublicKey());
    }

    @Then("the CRL contains the revoked serial")
    public void crlContainsSerial() throws Exception {
        X509CRL crl = parseCrl(lastCrlPem);
        BigInteger serial = new BigInteger(lastCertDto.getSerialNumber(), 16);
        assertThat(crl.getRevokedCertificate(serial)).isNotNull();
    }

    // ---- OCSP -----------------------------------------------------

    @When("an OCSP request is built for that certificate")
    public void buildOcspReq() throws Exception {
        X509Certificate cert = PemUtils.readCertificate(lastCertDto.getCertificatePem());
        TenantCertificateAuthority ca = casByTenant.values().iterator().next();
        X509Certificate caCert = PemUtils.readCertificate(ca.getCertificatePem());
        CertificateID id = new JcaCertificateID(
                new JcaDigestCalculatorProviderBuilder().build().get(CertificateID.HASH_SHA1),
                caCert, cert.getSerialNumber());
        OCSPReqBuilder b = new OCSPReqBuilder();
        b.addRequest(id);
        lastOcspReq = b.build();
    }

    @When("OCSP is asked for the status")
    public void askOcsp() throws Exception {
        Tenant t = casByTenant.keySet().iterator().next() != null
                ? world.tenants.values().iterator().next() : null;
        byte[] respBytes = ocspService.respond(t.getId(), lastOcspReq.getEncoded());
        lastOcspResp = new OCSPResp(respBytes);
    }

    @Then("the OCSP response status is {string}")
    public void ocspStatusIs(String expected) throws Exception {
        assertThat(lastOcspResp.getStatus()).isEqualTo(OCSPResponseStatus.SUCCESSFUL);
        BasicOCSPResp basic = (BasicOCSPResp) lastOcspResp.getResponseObject();
        SingleResp single = basic.getResponses()[0];
        CertificateStatus status = single.getCertStatus();
        switch (expected) {
            case "GOOD" -> assertThat(status).isNull(); // BC uses null for GOOD
            case "REVOKED" -> assertThat(status).isInstanceOf(RevokedStatus.class);
            default -> throw new AssertionError("Unsupported expected status " + expected);
        }
    }

    // ---- Client cert auth -----------------------------------------

    @When("the client cert authenticator validates that certificate")
    public void clientCertValidate() {
        X509Certificate cert = PemUtils.readCertificate(lastCertDto.getCertificatePem());
        lastAuthResult = clientCertAuth.authenticate(cert);
    }

    @Then("the authentication result is success")
    public void authSuccess() {
        assertThat(lastAuthResult.success()).isTrue();
    }

    @Then("the authentication result is failure")
    public void authFailure() {
        assertThat(lastAuthResult.success()).isFalse();
    }

    @Then("the authenticated user email is {string}")
    public void authedUserIs(String email) {
        assertThat(lastAuthResult.user().getEmail()).isEqualToIgnoringCase(email);
    }

    // ---- Helpers --------------------------------------------------

    private static X509CRL parseCrl(String pem) throws Exception {
        String b64 = pem
                .replace("-----BEGIN X509 CRL-----", "")
                .replace("-----END X509 CRL-----", "")
                .replaceAll("\\s", "");
        byte[] der = java.util.Base64.getDecoder().decode(b64);
        java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
        return (X509CRL) cf.generateCRL(new java.io.ByteArrayInputStream(der));
    }
}
