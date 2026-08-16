package tech.cwvermaak.weldforge.service.saml;

import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import tech.cwvermaak.weldforge.service.pki.PemUtils;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

/**
 * Test-only crypto helpers: generate an RSA key pair, mint a self-signed
 * certificate PEM, and produce a validly XML-signed AuthnRequest — so the
 * SAML signature-verification tests exercise real signatures end-to-end.
 */
public final class SamlTestCrypto {

    private SamlTestCrypto() {}

    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    public static String selfSignedCertPem(KeyPair kp) throws Exception {
        org.bouncycastle.asn1.x500.X500Name dn = new org.bouncycastle.asn1.x500.X500Name("CN=test-sp");
        Date from = new Date(System.currentTimeMillis() - 60_000);
        Date to = new Date(System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                dn, BigInteger.valueOf(System.nanoTime()), from, to, dn, kp.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(builder.build(signer));
        return PemUtils.writeCertificate(cert);
    }

    /** A minimal, namespaced AuthnRequest with the given issuer and ID. */
    public static String authnRequest(String issuer, String id) {
        return "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" "
                + "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"" + id + "\" Version=\"2.0\" "
                + "IssueInstant=\"2024-01-01T00:00:00Z\">"
                + "<saml:Issuer>" + issuer + "</saml:Issuer>"
                + "</samlp:AuthnRequest>";
    }

    /** Sign the AuthnRequest with an enveloped XML-DSig signature over the root. */
    public static String sign(String xml, KeyPair kp) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder()
                .parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
        Element root = doc.getDocumentElement();
        String id = root.getAttribute("ID");
        root.setIdAttribute("ID", true);

        XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");
        Reference ref = fac.newReference(
                "#" + id,
                fac.newDigestMethod(DigestMethod.SHA256, null),
                List.of(fac.newTransform(Transform.ENVELOPED, (javax.xml.crypto.dsig.spec.TransformParameterSpec) null),
                        fac.newTransform(CanonicalizationMethod.EXCLUSIVE, (javax.xml.crypto.dsig.spec.TransformParameterSpec) null)),
                null, null);
        SignedInfo si = fac.newSignedInfo(
                fac.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (javax.xml.crypto.dsig.spec.C14NMethodParameterSpec) null),
                fac.newSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", null),
                List.of(ref));
        KeyInfoFactory kif = fac.getKeyInfoFactory();
        KeyValue kv = kif.newKeyValue(kp.getPublic());
        KeyInfo ki = kif.newKeyInfo(List.of(kv));

        DOMSignContext dsc = new DOMSignContext(kp.getPrivate(), root);
        XMLSignature signature = fac.newXMLSignature(si, ki);
        signature.sign(dsc);

        return serialize(doc);
    }

    private static String serialize(Document doc) throws Exception {
        Transformer t = TransformerFactory.newInstance().newTransformer();
        t.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        StringWriter sw = new StringWriter();
        t.transform(new DOMSource(doc), new StreamResult(sw));
        return sw.toString();
    }
}
