package tech.cwvermaak.intellisso.service.saml;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallerFactory;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.core.impl.*;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.impl.SignatureBuilder;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.Signer;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import tech.cwvermaak.intellisso.config.tenant.TenantAccessor;
import tech.cwvermaak.intellisso.model.*;
import tech.cwvermaak.intellisso.model.dto.SamlServiceProviderDto;
import tech.cwvermaak.intellisso.repository.SamlServiceProviderRepository;
import tech.cwvermaak.intellisso.repository.ScimGroupRepository;
import tech.cwvermaak.intellisso.repository.UserRepository;
import tech.cwvermaak.intellisso.service.audit.AuditEventTypes;
import tech.cwvermaak.intellisso.service.audit.AuditService;
import tech.cwvermaak.intellisso.service.oidc.TenantSigningKeyService;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

/**
 * SAML 2.0 Identity Provider service. Issues signed SAML assertions to
 * registered downstream Service Providers using the tenant's RSA signing key.
 *
 * Reuses {@link TenantSigningKeyService} for key management — the same
 * per-tenant RSA keys that sign OIDC tokens also sign SAML assertions.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SamlIdpService {

    private static volatile boolean openSamlInitialised = false;

    private final TenantAccessor tenantAccessor;
    private final SamlServiceProviderRepository spRepository;
    private final TenantSigningKeyService signingKeyService;
    private final UserRepository userRepository;
    private final ScimGroupRepository scimGroupRepository;
    private final AuditService auditService;

    // ---- CRUD for SP registrations ----------------------------------

    @Transactional
    public SamlServiceProviderDto create(SamlServiceProviderDto dto) {
        Tenant tenant = tenantAccessor.requireTenant();
        if (dto.getEntityId() == null || dto.getEntityId().isBlank()) {
            throw new IllegalArgumentException("entityId is required");
        }
        if (dto.getAcsUrl() == null || dto.getAcsUrl().isBlank()) {
            throw new IllegalArgumentException("acsUrl is required");
        }
        if (spRepository.findByTenantIdAndEntityId(tenant.getId(), dto.getEntityId()).isPresent()) {
            throw new IllegalArgumentException("SP with this entityId already registered for tenant");
        }

        SamlServiceProvider sp = SamlServiceProvider.builder()
                .tenant(tenant)
                .entityId(dto.getEntityId())
                .name(dto.getName())
                .acsUrl(dto.getAcsUrl())
                .sloUrl(dto.getSloUrl())
                .spCertificate(dto.getSpCertificate())
                .nameIdFormat(dto.getNameIdFormat() != null ? dto.getNameIdFormat()
                        : "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
                .attributeMappings(dto.getAttributeMappings())
                .enabled(dto.getEnabled() != null ? dto.getEnabled() : true)
                .build();
        spRepository.save(sp);

        auditService.recordAdmin(AuditEventTypes.SAML_SP_CREATE, null,
                AuditEventTypes.TARGET_SAML_SP, String.valueOf(sp.getId()),
                AuditService.meta("entity_id", sp.getEntityId(), "name", sp.getName()));

        return toDto(sp);
    }

    @Transactional
    public SamlServiceProviderDto update(Long id, SamlServiceProviderDto dto) {
        Long tid = tenantAccessor.requireTenantId();
        SamlServiceProvider sp = spRepository.findByIdAndTenantId(id, tid)
                .orElseThrow(() -> new EntityNotFoundException("SP " + id + " not found"));

        if (dto.getName() != null) sp.setName(dto.getName());
        if (dto.getAcsUrl() != null) sp.setAcsUrl(dto.getAcsUrl());
        if (dto.getSloUrl() != null) sp.setSloUrl(dto.getSloUrl());
        if (dto.getSpCertificate() != null) sp.setSpCertificate(dto.getSpCertificate());
        if (dto.getNameIdFormat() != null) sp.setNameIdFormat(dto.getNameIdFormat());
        if (dto.getAttributeMappings() != null) sp.setAttributeMappings(dto.getAttributeMappings());
        if (dto.getEnabled() != null) sp.setEnabled(dto.getEnabled());

        auditService.recordAdmin(AuditEventTypes.SAML_SP_UPDATE, null,
                AuditEventTypes.TARGET_SAML_SP, String.valueOf(sp.getId()),
                AuditService.meta("entity_id", sp.getEntityId()));

        return toDto(sp);
    }

    @Transactional
    public void delete(Long id) {
        Long tid = tenantAccessor.requireTenantId();
        SamlServiceProvider sp = spRepository.findByIdAndTenantId(id, tid)
                .orElseThrow(() -> new EntityNotFoundException("SP " + id + " not found"));
        spRepository.delete(sp);

        auditService.recordAdmin(AuditEventTypes.SAML_SP_DELETE, null,
                AuditEventTypes.TARGET_SAML_SP, String.valueOf(id),
                AuditService.meta("entity_id", sp.getEntityId()));
    }

    public List<SamlServiceProviderDto> list() {
        Long tid = tenantAccessor.requireTenantId();
        return spRepository.findByTenantId(tid).stream().map(SamlIdpService::toDto).toList();
    }

    // ---- IdP metadata -----------------------------------------------

    public String generateMetadata(Tenant tenant, String baseUrl) {
        ensureOpenSaml();
        TenantSigningKey key = signingKeyService.getOrCreateActive(tenant);
        RSAPublicKey publicKey = signingKeyService.loadPublicKey(key);
        String slug = tenant.getSlug();

        String entityId = baseUrl + "/t/" + slug + "/saml2/idp/metadata";
        String ssoLocation = baseUrl + "/t/" + slug + "/saml2/idp/sso";

        StringBuilder xml = new StringBuilder();
        xml.append("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.append("<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\"");
        xml.append(" xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"");
        xml.append(" entityID=\"").append(escapeXml(entityId)).append("\">\n");
        xml.append("  <md:IDPSSODescriptor WantAuthnRequestsSigned=\"false\"");
        xml.append(" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">\n");

        // Signing key
        xml.append("    <md:KeyDescriptor use=\"signing\">\n");
        xml.append("      <ds:KeyInfo>\n");
        xml.append("        <ds:X509Data>\n");
        xml.append("          <ds:X509Certificate>");
        xml.append(base64EncodedPublicKey(publicKey));
        xml.append("</ds:X509Certificate>\n");
        xml.append("        </ds:X509Data>\n");
        xml.append("      </ds:KeyInfo>\n");
        xml.append("    </md:KeyDescriptor>\n");

        // NameID formats
        xml.append("    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>\n");
        xml.append("    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>\n");

        // SSO endpoints
        xml.append("    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"");
        xml.append(" Location=\"").append(escapeXml(ssoLocation)).append("\"/>\n");
        xml.append("    <md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\"");
        xml.append(" Location=\"").append(escapeXml(ssoLocation)).append("\"/>\n");

        xml.append("  </md:IDPSSODescriptor>\n");
        xml.append("</md:EntityDescriptor>");

        return xml.toString();
    }

    // ---- SAML Response builder --------------------------------------

    /**
     * Build a signed SAML Response + Assertion for the given user and SP.
     * Returns the base64-encoded XML response ready for POST binding.
     */
    public String buildSamlResponse(Tenant tenant, User user, SamlServiceProvider sp,
                                     String inResponseTo) {
        ensureOpenSaml();

        TenantSigningKey key = signingKeyService.getOrCreateActive(tenant);
        RSAPrivateKey privateKey = signingKeyService.loadPrivateKey(key);
        RSAPublicKey publicKey = signingKeyService.loadPublicKey(key);

        String issuer = tenant.getSlug() + "-idp";
        Instant now = Instant.now();
        String responseId = "_" + UUID.randomUUID();
        String assertionId = "_" + UUID.randomUUID();

        // Collect user attributes
        List<String> groupNames = collectGroupNames(tenant.getId(), user.getId());
        String roleName = user.getRole() != null ? user.getRole().getName() : null;

        try {
            // Build the response XML manually for reliability across OpenSAML versions
            String nameId = resolveNameId(user, sp.getNameIdFormat());
            String xml = buildResponseXml(responseId, assertionId, issuer, sp.getEntityId(),
                    sp.getAcsUrl(), inResponseTo, nameId, sp.getNameIdFormat(),
                    user, groupNames, roleName, sp.getAttributeMappings(), now);

            // Sign the response
            String signedXml = signXml(xml, assertionId, privateKey, publicKey);

            auditService.recordUserAction(AuditEventTypes.SAML_IDP_ASSERTION_ISSUED, user,
                    AuditEventTypes.TARGET_SAML_SP, String.valueOf(sp.getId()),
                    AuditService.meta("sp_entity_id", sp.getEntityId(),
                            "assertion_id", assertionId));

            return Base64.getEncoder().encodeToString(signedXml.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build SAML response", e);
        }
    }

    // ---- AuthnRequest validation ------------------------------------

    /**
     * Validate an incoming AuthnRequest. Returns the matched SP if the
     * issuer is a registered, enabled SP for this tenant.
     */
    public SamlServiceProvider validateAuthnRequest(Tenant tenant, String issuer) {
        if (issuer == null || issuer.isBlank()) {
            throw new IllegalArgumentException("AuthnRequest issuer is required");
        }
        return spRepository.findByTenantIdAndEntityId(tenant.getId(), issuer)
                .filter(SamlServiceProvider::getEnabled)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Unregistered or disabled SP: " + issuer));
    }

    // ---- Helpers ----------------------------------------------------

    private List<String> collectGroupNames(Long tenantId, Long userId) {
        return scimGroupRepository.findByTenantId(tenantId).stream()
                .filter(g -> g.getMembers().stream().anyMatch(u -> u.getId().equals(userId)))
                .map(ScimGroup::getDisplayName)
                .collect(Collectors.toList());
    }

    private static String resolveNameId(User user, String nameIdFormat) {
        if (nameIdFormat != null && nameIdFormat.contains("persistent")) {
            return String.valueOf(user.getId());
        }
        return user.getEmail();
    }

    private String buildResponseXml(String responseId, String assertionId, String issuer,
                                     String audience, String acsUrl, String inResponseTo,
                                     String nameId, String nameIdFormat,
                                     User user, List<String> groups, String roleName,
                                     Map<String, Object> attrMappings, Instant now) {
        String notBefore = now.minusSeconds(60).toString();
        String notOnOrAfter = now.plusSeconds(300).toString();
        String issueInstant = now.toString();

        String emailAttr = mapAttr("email", attrMappings);
        String nameAttr = mapAttr("name", attrMappings);
        String groupsAttr = mapAttr("groups", attrMappings);
        String roleAttr = mapAttr("role", attrMappings);

        StringBuilder xml = new StringBuilder();
        xml.append("<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"");
        xml.append(" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"");
        xml.append(" ID=\"").append(responseId).append("\"");
        xml.append(" Version=\"2.0\"");
        xml.append(" IssueInstant=\"").append(issueInstant).append("\"");
        xml.append(" Destination=\"").append(escapeXml(acsUrl)).append("\"");
        if (inResponseTo != null) xml.append(" InResponseTo=\"").append(escapeXml(inResponseTo)).append("\"");
        xml.append(">\n");

        xml.append("  <saml:Issuer>").append(escapeXml(issuer)).append("</saml:Issuer>\n");
        xml.append("  <samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>\n");

        // Assertion
        xml.append("  <saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"");
        xml.append(" ID=\"").append(assertionId).append("\"");
        xml.append(" Version=\"2.0\"");
        xml.append(" IssueInstant=\"").append(issueInstant).append("\">\n");
        xml.append("    <saml:Issuer>").append(escapeXml(issuer)).append("</saml:Issuer>\n");

        // Subject
        xml.append("    <saml:Subject>\n");
        xml.append("      <saml:NameID Format=\"").append(escapeXml(nameIdFormat)).append("\">");
        xml.append(escapeXml(nameId)).append("</saml:NameID>\n");
        xml.append("      <saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">\n");
        xml.append("        <saml:SubjectConfirmationData");
        xml.append(" NotOnOrAfter=\"").append(notOnOrAfter).append("\"");
        xml.append(" Recipient=\"").append(escapeXml(acsUrl)).append("\"");
        if (inResponseTo != null) xml.append(" InResponseTo=\"").append(escapeXml(inResponseTo)).append("\"");
        xml.append("/>\n");
        xml.append("      </saml:SubjectConfirmation>\n");
        xml.append("    </saml:Subject>\n");

        // Conditions
        xml.append("    <saml:Conditions NotBefore=\"").append(notBefore).append("\"");
        xml.append(" NotOnOrAfter=\"").append(notOnOrAfter).append("\">\n");
        xml.append("      <saml:AudienceRestriction>\n");
        xml.append("        <saml:Audience>").append(escapeXml(audience)).append("</saml:Audience>\n");
        xml.append("      </saml:AudienceRestriction>\n");
        xml.append("    </saml:Conditions>\n");

        // AuthnStatement
        xml.append("    <saml:AuthnStatement AuthnInstant=\"").append(issueInstant).append("\">\n");
        xml.append("      <saml:AuthnContext>\n");
        xml.append("        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>\n");
        xml.append("      </saml:AuthnContext>\n");
        xml.append("    </saml:AuthnStatement>\n");

        // AttributeStatement
        xml.append("    <saml:AttributeStatement>\n");
        appendAttribute(xml, emailAttr, user.getEmail());
        if (user.getName() != null) appendAttribute(xml, nameAttr, user.getName());
        appendAttribute(xml, "sub", String.valueOf(user.getId()));
        if (roleName != null) appendAttribute(xml, roleAttr, roleName);
        if (!groups.isEmpty()) {
            for (String g : groups) {
                appendAttribute(xml, groupsAttr, g);
            }
        }
        xml.append("    </saml:AttributeStatement>\n");

        xml.append("  </saml:Assertion>\n");
        xml.append("</samlp:Response>");

        return xml.toString();
    }

    private static void appendAttribute(StringBuilder xml, String name, String value) {
        xml.append("      <saml:Attribute Name=\"").append(escapeXml(name)).append("\">\n");
        xml.append("        <saml:AttributeValue>").append(escapeXml(value)).append("</saml:AttributeValue>\n");
        xml.append("      </saml:Attribute>\n");
    }

    private static String mapAttr(String standard, Map<String, Object> mappings) {
        if (mappings != null && mappings.containsKey(standard)) {
            return String.valueOf(mappings.get(standard));
        }
        return standard;
    }

    private String signXml(String xml, String assertionId,
                           RSAPrivateKey privateKey, RSAPublicKey publicKey) throws Exception {
        // For the initial implementation, we embed the XML-DSig signature
        // using Java's built-in XML signature API.
        javax.xml.parsers.DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder()
                .parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));

        // Find the Assertion element to sign
        org.w3c.dom.NodeList assertions = doc.getElementsByTagNameNS(
                "urn:oasis:names:tc:SAML:2.0:assertion", "Assertion");
        if (assertions.getLength() == 0) {
            throw new IllegalStateException("No Assertion element found in SAML response");
        }
        Element assertionElement = (Element) assertions.item(0);
        // Register the ID attribute so the XML-DSig resolver can find it by URI fragment
        assertionElement.setIdAttribute("ID", true);

        // Create XML Signature
        javax.xml.crypto.dsig.XMLSignatureFactory fac =
                javax.xml.crypto.dsig.XMLSignatureFactory.getInstance("DOM");

        javax.xml.crypto.dsig.Reference ref = fac.newReference(
                "#" + assertionId,
                fac.newDigestMethod(javax.xml.crypto.dsig.DigestMethod.SHA256, null),
                List.of(
                    fac.newTransform(javax.xml.crypto.dsig.Transform.ENVELOPED, (javax.xml.crypto.dsig.spec.TransformParameterSpec) null),
                    fac.newCanonicalizationMethod(javax.xml.crypto.dsig.CanonicalizationMethod.EXCLUSIVE, (javax.xml.crypto.dsig.spec.C14NMethodParameterSpec) null)
                ),
                null, null);

        javax.xml.crypto.dsig.SignedInfo si = fac.newSignedInfo(
                fac.newCanonicalizationMethod(javax.xml.crypto.dsig.CanonicalizationMethod.EXCLUSIVE,
                        (javax.xml.crypto.dsig.spec.C14NMethodParameterSpec) null),
                fac.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", null),
                List.of(ref));

        java.security.KeyPair kp = new java.security.KeyPair(publicKey, privateKey);
        javax.xml.crypto.dsig.keyinfo.KeyInfoFactory kif = fac.getKeyInfoFactory();
        javax.xml.crypto.dsig.keyinfo.KeyValue kv = kif.newKeyValue(publicKey);
        javax.xml.crypto.dsig.keyinfo.KeyInfo ki = kif.newKeyInfo(List.of(kv));

        javax.xml.crypto.dsig.XMLSignature signature = fac.newXMLSignature(si, ki);

        // Sign — insert signature as first child of Assertion (after Issuer)
        org.w3c.dom.NodeList issuerNodes = assertionElement.getElementsByTagNameNS(
                "urn:oasis:names:tc:SAML:2.0:assertion", "Issuer");
        org.w3c.dom.Node insertBefore = issuerNodes.getLength() > 0
                ? issuerNodes.item(0).getNextSibling() : assertionElement.getFirstChild();

        javax.xml.crypto.dsig.dom.DOMSignContext dsc =
                new javax.xml.crypto.dsig.dom.DOMSignContext(privateKey, assertionElement, insertBefore);
        signature.sign(dsc);

        // Serialize
        javax.xml.transform.TransformerFactory tf = javax.xml.transform.TransformerFactory.newInstance();
        javax.xml.transform.Transformer transformer = tf.newTransformer();
        transformer.setOutputProperty(javax.xml.transform.OutputKeys.OMIT_XML_DECLARATION, "yes");
        java.io.StringWriter sw = new java.io.StringWriter();
        transformer.transform(new javax.xml.transform.dom.DOMSource(doc),
                new javax.xml.transform.stream.StreamResult(sw));
        return sw.toString();
    }

    static SamlServiceProviderDto toDto(SamlServiceProvider sp) {
        return SamlServiceProviderDto.builder()
                .id(sp.getId())
                .entityId(sp.getEntityId())
                .name(sp.getName())
                .acsUrl(sp.getAcsUrl())
                .sloUrl(sp.getSloUrl())
                .spCertificate(sp.getSpCertificate())
                .nameIdFormat(sp.getNameIdFormat())
                .attributeMappings(sp.getAttributeMappings())
                .enabled(sp.getEnabled())
                .build();
    }

    private static String escapeXml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&apos;");
    }

    private static String base64EncodedPublicKey(RSAPublicKey publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    private static synchronized void ensureOpenSaml() {
        if (openSamlInitialised) return;
        try {
            InitializationService.initialize();
            openSamlInitialised = true;
        } catch (InitializationException e) {
            log.warn("OpenSAML init failed (may already be initialised): {}", e.getMessage());
            openSamlInitialised = true;
        }
    }
}
