package tech.cwvermaak.intellisso.service.saml;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import tech.cwvermaak.intellisso.model.dto.SamlProviderDto;
import tech.cwvermaak.intellisso.model.dto.SamlServiceProviderDto;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

/**
 * Parses a SAML 2.0 {@code EntityDescriptor} XML document and extracts
 * the fields needed to populate a {@link SamlServiceProviderDto} (when
 * importing a downstream SP) or a {@link SamlProviderDto} (when importing
 * an upstream IdP). Supports both direct XML and URL fetch.
 *
 * PRD: SAM-05.
 *
 * Intentionally forgiving about namespace prefixes — different producers
 * emit {@code md:}, {@code xmlns:} or unprefixed elements, but they're
 * all in the {@code urn:oasis:names:tc:SAML:2.0:metadata} namespace.
 */
@Service
@Slf4j
public class SamlMetadataParser {

    private static final String MD_NS    = "urn:oasis:names:tc:SAML:2.0:metadata";
    private static final String DSIG_NS  = "http://www.w3.org/2000/09/xmldsig#";
    private static final String POST_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();

    // ---- Public API ------------------------------------------------

    /** Fetch metadata from a URL and parse it. */
    public ParsedMetadata importFromUrl(String url) {
        if (url == null || url.isBlank()) {
            throw new IllegalArgumentException("metadataUrl is required");
        }
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                    .timeout(Duration.ofSeconds(15))
                    .header("Accept", "application/samlmetadata+xml, application/xml, text/xml, */*")
                    .GET()
                    .build();
            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() >= 400) {
                throw new IllegalArgumentException(
                        "Metadata fetch failed: HTTP " + resp.statusCode() + " from " + url);
            }
            return parseXml(resp.body());
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Metadata fetch failed: " + e.getMessage(), e);
        }
    }

    /** Parse raw EntityDescriptor XML. */
    public ParsedMetadata parseXml(String xml) {
        if (xml == null || xml.isBlank()) {
            throw new IllegalArgumentException("metadataXml is required");
        }
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            // Prevent XXE.
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            DocumentBuilder db = dbf.newDocumentBuilder();

            Document doc = db.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
            Element root = doc.getDocumentElement();

            // Root may be EntityDescriptor directly, or EntitiesDescriptor wrapping one.
            Element entity = firstElementNS(root, MD_NS, "EntityDescriptor");
            if (entity == null && "EntityDescriptor".equals(root.getLocalName())) {
                entity = root;
            }
            if (entity == null) {
                throw new IllegalArgumentException("No EntityDescriptor found in metadata");
            }

            String entityId = entity.getAttribute("entityID");
            if (entityId == null || entityId.isBlank()) {
                throw new IllegalArgumentException("EntityDescriptor is missing entityID");
            }

            Element sp  = firstElementNS(entity, MD_NS, "SPSSODescriptor");
            Element idp = firstElementNS(entity, MD_NS, "IDPSSODescriptor");

            if (sp != null) {
                return parseSp(entityId, sp);
            } else if (idp != null) {
                return parseIdp(entityId, idp);
            } else {
                throw new IllegalArgumentException(
                        "EntityDescriptor has neither SPSSODescriptor nor IDPSSODescriptor");
            }
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Could not parse SAML metadata: " + e.getMessage(), e);
        }
    }

    // ---- Parsing ---------------------------------------------------

    private ParsedMetadata parseSp(String entityId, Element spDescriptor) {
        // Assertion Consumer Service — prefer HTTP-POST binding.
        String acsUrl = preferredBindingLocation(spDescriptor, "AssertionConsumerService");
        // SLO endpoint (optional).
        String sloUrl = preferredBindingLocation(spDescriptor, "SingleLogoutService");
        // Signing certificate (optional — for SP-signed AuthnRequests).
        String cert = signingCertificate(spDescriptor);
        // NameID format preference (first one declared).
        String nameIdFormat = firstTextNS(spDescriptor, MD_NS, "NameIDFormat");

        SamlServiceProviderDto dto = SamlServiceProviderDto.builder()
                .entityId(entityId)
                .acsUrl(acsUrl)
                .sloUrl(sloUrl)
                .spCertificate(cert)
                .nameIdFormat(nameIdFormat != null ? nameIdFormat
                        : "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
                .enabled(true)
                .build();
        return new ParsedMetadata(ParsedKind.SP, dto, null);
    }

    private ParsedMetadata parseIdp(String entityId, Element idpDescriptor) {
        // Upstream IdP — we import these into tenant_saml_providers.
        String ssoUrl = preferredBindingLocation(idpDescriptor, "SingleSignOnService");
        String sloUrl = preferredBindingLocation(idpDescriptor, "SingleLogoutService");
        String cert = signingCertificate(idpDescriptor);

        SamlProviderDto dto = SamlProviderDto.builder()
                .idpEntityId(entityId)
                .idpSsoUrl(ssoUrl)
                .idpSloUrl(sloUrl)
                .idpSigningCertificate(cert)
                .ssoBinding(tech.cwvermaak.intellisso.model.TenantSamlProvider.Binding.POST)
                .emailAttribute("email")
                .nameAttribute("name")
                .wantAssertionsSigned(true)
                .wantAuthnRequestSigned(false)
                .enabled(true)
                .build();
        return new ParsedMetadata(ParsedKind.IDP, null, dto);
    }

    // ---- DOM helpers -----------------------------------------------

    /** Find the location of the first matching service element, preferring HTTP-POST. */
    private String preferredBindingLocation(Element descriptor, String localName) {
        NodeList services = descriptor.getElementsByTagNameNS(MD_NS, localName);
        String fallback = null;
        for (int i = 0; i < services.getLength(); i++) {
            Element svc = (Element) services.item(i);
            String binding = svc.getAttribute("Binding");
            String location = svc.getAttribute("Location");
            if (location == null || location.isBlank()) continue;
            if (POST_BINDING.equals(binding)) return location;
            if (fallback == null) fallback = location;
        }
        return fallback;
    }

    /**
     * Extract the signing certificate from a {@code KeyDescriptor}, preferring
     * {@code use="signing"} but falling back to any {@code X509Certificate}
     * if no {@code use} attribute is set.
     */
    private String signingCertificate(Element descriptor) {
        NodeList keyDescriptors = descriptor.getElementsByTagNameNS(MD_NS, "KeyDescriptor");
        String fallback = null;
        for (int i = 0; i < keyDescriptors.getLength(); i++) {
            Element kd = (Element) keyDescriptors.item(i);
            String use = kd.getAttribute("use");
            String cert = firstCertificate(kd);
            if (cert == null) continue;
            if ("signing".equals(use)) return formatPem(cert);
            if (use == null || use.isBlank()) fallback = cert;
        }
        return fallback != null ? formatPem(fallback) : null;
    }

    private String firstCertificate(Element keyDescriptor) {
        NodeList certs = keyDescriptor.getElementsByTagNameNS(DSIG_NS, "X509Certificate");
        if (certs.getLength() == 0) return null;
        String text = certs.item(0).getTextContent();
        return text == null || text.isBlank() ? null : text.replaceAll("\\s+", "");
    }

    /** Wrap a bare base64 cert blob in PEM framing. */
    private static String formatPem(String b64) {
        if (b64 == null) return null;
        StringBuilder sb = new StringBuilder("-----BEGIN CERTIFICATE-----\n");
        for (int i = 0; i < b64.length(); i += 64) {
            sb.append(b64, i, Math.min(i + 64, b64.length())).append('\n');
        }
        sb.append("-----END CERTIFICATE-----");
        return sb.toString();
    }

    private static Element firstElementNS(Element parent, String ns, String local) {
        NodeList n = parent.getElementsByTagNameNS(ns, local);
        return n.getLength() > 0 ? (Element) n.item(0) : null;
    }

    private static String firstTextNS(Element parent, String ns, String local) {
        NodeList n = parent.getElementsByTagNameNS(ns, local);
        if (n.getLength() == 0) return null;
        String text = n.item(0).getTextContent();
        return text == null ? null : text.trim();
    }

    // ---- Result type -----------------------------------------------

    public enum ParsedKind { SP, IDP }

    /**
     * Result of parsing an {@code EntityDescriptor}. Exactly one of
     * {@code spDto} / {@code idpDto} is populated based on {@code kind}.
     */
    public record ParsedMetadata(ParsedKind kind,
                                 SamlServiceProviderDto spDto,
                                 SamlProviderDto idpDto) {}
}
