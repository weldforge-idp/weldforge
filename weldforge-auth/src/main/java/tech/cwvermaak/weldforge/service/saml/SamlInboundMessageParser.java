package tech.cwvermaak.weldforge.service.saml;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

/**
 * Parses inbound SAML 2.0 protocol messages (AuthnRequest / LogoutRequest)
 * with an XXE-hardened, namespace-aware DOM parser, and pulls out the fields
 * the IdP needs: the SP's {@code Issuer} and the message {@code ID}.
 *
 * <p>This replaces the previous {@code indexOf}/substring string-scanning,
 * which was bypassable (namespace-prefix tricks, comments, CDATA, attribute
 * ordering) and offered no XXE protection (B-SAML-1). Parsing the real DOM is
 * also a prerequisite for verifying the AuthnRequest signature, since the
 * signature covers the parsed document, not the raw bytes.
 */
public final class SamlInboundMessageParser {

    private static final String SAML_ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String SAML_PROTOCOL_NS = "urn:oasis:names:tc:SAML:2.0:protocol";

    /**
     * Extracted fields of an inbound SAML protocol message.
     *
     * @param issueInstant   the root {@code IssueInstant}, or null when absent
     *                       or unparseable -- the caller decides what that means
     * @param nameId         the {@code LogoutRequest} subject, or null
     * @param sessionIndexes every {@code LogoutRequest} {@code SessionIndex}; empty
     *                       for an AuthnRequest or a logout naming no session
     */
    public record ParsedMessage(String rootLocalName, String issuer, String messageId,
                                java.time.Instant issueInstant, String nameId,
                                java.util.List<String> sessionIndexes) {

        /** Back-compat shape for callers that only need the routing fields. */
        public ParsedMessage(String rootLocalName, String issuer, String messageId) {
            this(rootLocalName, issuer, messageId, null, null, java.util.List.of());
        }
    }

    private SamlInboundMessageParser() {}

    /**
     * Parse an inbound SAML message.
     *
     * @throws SamlMessageException if the XML is empty, malformed, or declares
     *         a DOCTYPE (rejected to prevent XML External Entity attacks)
     */
    public static ParsedMessage parse(String xml) {
        Document doc = parseHardened(xml);
        try {
            Element root = doc.getDocumentElement();
            if (root == null) {
                throw new SamlMessageException("SAML message has no root element");
            }
            String rootLocal = localName(root);
            String messageId = emptyToNull(root.getAttribute("ID"));
            String issuer = firstIssuer(doc);
            return new ParsedMessage(rootLocal, issuer, messageId,
                    parseInstant(root.getAttribute("IssueInstant")),
                    firstText(doc, SAML_ASSERTION_NS, "NameID"),
                    allText(doc, SAML_PROTOCOL_NS, "SessionIndex"));
        } catch (SamlMessageException e) {
            throw e;
        } catch (Exception e) {
            // Covers DOCTYPE rejection, malformed XML, encoding errors, etc.
            throw new SamlMessageException("invalid SAML message: " + e.getMessage());
        }
    }

    /**
     * Parse SAML XML into a DOM with all the XXE defenses applied (DOCTYPE
     * forbidden, external entities disabled, secure processing). Shared with
     * {@link SamlSignatureValidator} so signature verification runs over the
     * same hardened parse. Package-visible.
     *
     * @throws SamlMessageException on empty, malformed, or DOCTYPE-bearing input
     */
    static Document parseHardened(String xml) {
        if (xml == null || xml.isBlank()) {
            throw new SamlMessageException("empty SAML message");
        }
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            // XXE defenses: forbid DOCTYPE entirely and disable external entities.
            dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            dbf.setXIncludeAware(false);
            dbf.setExpandEntityReferences(false);
            DocumentBuilder db = dbf.newDocumentBuilder();
            return db.parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new SamlMessageException("invalid SAML message: " + e.getMessage());
        }
    }

    /**
     * The {@code <saml:Issuer>} text. Prefers the proper SAML assertion
     * namespace; falls back to a local-name match for messages that don't
     * declare it, so we stay at least as lenient as the old scanner.
     */
    private static String firstIssuer(Document doc) {
        NodeList byNs = doc.getElementsByTagNameNS(SAML_ASSERTION_NS, "Issuer");
        if (byNs.getLength() > 0) {
            return emptyToNull(textContent(byNs.item(0)));
        }
        NodeList all = doc.getElementsByTagName("*");
        for (int i = 0; i < all.getLength(); i++) {
            Node n = all.item(i);
            if ("Issuer".equals(localName(n))) {
                return emptyToNull(textContent(n));
            }
        }
        return null;
    }

    /** xs:dateTime as SAML uses it (UTC, optional fraction); null when unusable. */
    private static java.time.Instant parseInstant(String raw) {
        if (raw == null || raw.isBlank()) return null;
        try {
            return java.time.OffsetDateTime.parse(raw.trim()).toInstant();
        } catch (java.time.format.DateTimeParseException e) {
            return null;
        }
    }

    private static String firstText(Document doc, String ns, String local) {
        NodeList nodes = doc.getElementsByTagNameNS(ns, local);
        return nodes.getLength() == 0 ? null : emptyToNull(textContent(nodes.item(0)));
    }

    private static java.util.List<String> allText(Document doc, String ns, String local) {
        NodeList nodes = doc.getElementsByTagNameNS(ns, local);
        java.util.List<String> out = new java.util.ArrayList<>();
        for (int i = 0; i < nodes.getLength(); i++) {
            String v = emptyToNull(textContent(nodes.item(i)));
            if (v != null) out.add(v);
        }
        return java.util.List.copyOf(out);
    }

    private static String localName(Node n) {
        return n.getLocalName() != null ? n.getLocalName() : n.getNodeName();
    }

    private static String textContent(Node n) {
        return n.getTextContent() == null ? null : n.getTextContent().trim();
    }

    private static String emptyToNull(String s) {
        return (s == null || s.isBlank()) ? null : s;
    }
}
