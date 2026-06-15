package tech.cwvermaak.weldforge.service.saml;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

/**
 * Verifies the enveloped XML-DSig signature on an inbound SAML message
 * (AuthnRequest / LogoutRequest) against an SP's public key (B-SAML-1 part a).
 *
 * <p>Hardened against XML Signature Wrapping (XSW): the message is parsed with
 * the XXE-hardened parser, the {@code ID} attribute is registered so reference
 * resolution is unambiguous, and the signature is accepted only when
 * <ul>
 *   <li>there is exactly one {@code ds:Signature},</li>
 *   <li>it is a direct child of the document root (enveloped over the message),</li>
 *   <li>it has exactly one {@code Reference} whose URI is {@code #<rootId>}, and</li>
 *   <li>secure validation is enabled (restricts transforms/algorithms).</li>
 * </ul>
 * Any deviation throws {@link SamlMessageException}.
 */
public final class SamlSignatureValidator {

    private static final String DSIG_NS = XMLSignature.XMLNS; // http://www.w3.org/2000/09/xmldsig#

    private SamlSignatureValidator() {}

    /** Verify the enveloped signature over the SAML message root. */
    public static void verify(String xml, PublicKey publicKey) {
        if (publicKey == null) {
            throw new SamlMessageException("no verification key available");
        }
        Document doc = SamlInboundMessageParser.parseHardened(xml);
        Element root = doc.getDocumentElement();
        if (root == null) {
            throw new SamlMessageException("SAML message has no root element");
        }
        String rootId = root.getAttribute("ID");
        if (rootId == null || rootId.isBlank()) {
            throw new SamlMessageException("signed SAML message has no ID");
        }
        // Register ID-ness so the Reference "#rootId" resolves to the root only.
        root.setIdAttribute("ID", true);

        NodeList sigs = doc.getElementsByTagNameNS(DSIG_NS, "Signature");
        if (sigs.getLength() == 0) {
            throw new SamlMessageException("SAML message is not signed");
        }
        if (sigs.getLength() > 1) {
            throw new SamlMessageException("SAML message has multiple signatures");
        }
        Element sigEl = (Element) sigs.item(0);
        // XSW guard: the signature must envelope the message root, not some
        // smuggled-in element elsewhere in the tree.
        if (sigEl.getParentNode() != root) {
            throw new SamlMessageException("signature is not enveloped over the message root");
        }

        try {
            XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
            DOMValidateContext ctx = new DOMValidateContext(publicKey, sigEl);
            ctx.setProperty("org.jcp.xml.dsig.secureValidation", Boolean.TRUE);
            XMLSignature signature = fac.unmarshalXMLSignature(ctx);

            List<?> refs = signature.getSignedInfo().getReferences();
            if (refs.size() != 1) {
                throw new SamlMessageException("signature must cover exactly one reference");
            }
            String uri = ((Reference) refs.get(0)).getURI();
            if (uri == null || !uri.equals("#" + rootId)) {
                throw new SamlMessageException("signature does not cover the message root");
            }
            if (!signature.validate(ctx)) {
                throw new SamlMessageException("invalid SAML signature");
            }
        } catch (SamlMessageException e) {
            throw e;
        } catch (Exception e) {
            throw new SamlMessageException("signature validation error: " + e.getMessage());
        }
    }

    /** Extract the public key from a PEM (or bare base64) X.509 certificate. */
    public static PublicKey publicKeyFromPem(String pem) {
        try {
            String trimmed = pem == null ? "" : pem.trim();
            String b64 = trimmed.startsWith("-----BEGIN")
                    ? trimmed.replaceAll("-----BEGIN [^-]+-----", "")
                             .replaceAll("-----END [^-]+-----", "")
                             .replaceAll("\\s", "")
                    : trimmed.replaceAll("\\s", "");
            byte[] der = Base64.getDecoder().decode(b64);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(der));
            return cert.getPublicKey();
        } catch (Exception e) {
            throw new SamlMessageException("invalid SP certificate: " + e.getMessage());
        }
    }
}
