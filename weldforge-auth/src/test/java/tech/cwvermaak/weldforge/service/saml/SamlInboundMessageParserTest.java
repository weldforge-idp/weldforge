package tech.cwvermaak.weldforge.service.saml;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Spec for the XXE-hardened inbound SAML parser (B-SAML-1). Comprehensive
 * positive and negative coverage: well-formed AuthnRequest/LogoutRequest are
 * parsed correctly, and hostile or malformed input is rejected — notably any
 * DOCTYPE, which is how XML External Entity attacks are delivered.
 */
class SamlInboundMessageParserTest {

    private static final String NS =
            "xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" "
          + "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"";

    // ---- positive ----------------------------------------------------

    @Test
    @DisplayName("parses a well-formed AuthnRequest: issuer, ID and root element")
    void parsesAuthnRequest() {
        String xml = "<samlp:AuthnRequest " + NS + " ID=\"_abc123\" Version=\"2.0\" "
                + "IssueInstant=\"2024-01-01T00:00:00Z\">"
                + "<saml:Issuer>https://sp.example.com/meta</saml:Issuer>"
                + "</samlp:AuthnRequest>";

        SamlInboundMessageParser.ParsedMessage m = SamlInboundMessageParser.parse(xml);

        assertThat(m.rootLocalName()).isEqualTo("AuthnRequest");
        assertThat(m.issuer()).isEqualTo("https://sp.example.com/meta");
        assertThat(m.messageId()).isEqualTo("_abc123");
    }

    @Test
    @DisplayName("parses a LogoutRequest the same way")
    void parsesLogoutRequest() {
        String xml = "<samlp:LogoutRequest " + NS + " ID=\"_lo1\" Version=\"2.0\" "
                + "IssueInstant=\"2024-01-01T00:00:00Z\">"
                + "<saml:Issuer>https://sp.example.com/meta</saml:Issuer>"
                + "</samlp:LogoutRequest>";

        SamlInboundMessageParser.ParsedMessage m = SamlInboundMessageParser.parse(xml);

        assertThat(m.rootLocalName()).isEqualTo("LogoutRequest");
        assertThat(m.issuer()).isEqualTo("https://sp.example.com/meta");
        assertThat(m.messageId()).isEqualTo("_lo1");
    }

    @Test
    @DisplayName("trims whitespace around the Issuer text")
    void trimsIssuer() {
        String xml = "<samlp:AuthnRequest " + NS + " ID=\"_x\">"
                + "<saml:Issuer>\n  https://sp.example.com/meta  \n</saml:Issuer>"
                + "</samlp:AuthnRequest>";

        assertThat(SamlInboundMessageParser.parse(xml).issuer())
                .isEqualTo("https://sp.example.com/meta");
    }

    @Test
    @DisplayName("a message without an Issuer yields a null issuer (not an exception)")
    void missingIssuerIsNull() {
        String xml = "<samlp:AuthnRequest " + NS + " ID=\"_x\"/>";

        SamlInboundMessageParser.ParsedMessage m = SamlInboundMessageParser.parse(xml);

        assertThat(m.issuer()).isNull();
        assertThat(m.messageId()).isEqualTo("_x");
    }

    // ---- negative ----------------------------------------------------

    @Test
    @DisplayName("rejects a message carrying a DOCTYPE — the XXE delivery vector")
    void rejectsDoctypeXxe() {
        String xxe = "<?xml version=\"1.0\"?>"
                + "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"
                + "<samlp:AuthnRequest " + NS + " ID=\"_x\">"
                + "<saml:Issuer>&xxe;</saml:Issuer></samlp:AuthnRequest>";

        assertThatThrownBy(() -> SamlInboundMessageParser.parse(xxe))
                .isInstanceOf(SamlMessageException.class);
    }

    @Test
    @DisplayName("rejects malformed XML")
    void rejectsMalformed() {
        assertThatThrownBy(() -> SamlInboundMessageParser.parse("<samlp:AuthnRequest not closed"))
                .isInstanceOf(SamlMessageException.class);
    }

    @Test
    @DisplayName("rejects empty or blank input")
    void rejectsEmpty() {
        assertThatThrownBy(() -> SamlInboundMessageParser.parse(null))
                .isInstanceOf(SamlMessageException.class);
        assertThatThrownBy(() -> SamlInboundMessageParser.parse("   "))
                .isInstanceOf(SamlMessageException.class);
    }
}
