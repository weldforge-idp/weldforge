package tech.cwvermaak.weldforge.service.saml;

/**
 * Thrown when an inbound SAML protocol message (AuthnRequest / LogoutRequest)
 * cannot be parsed safely — malformed XML, a disallowed DOCTYPE (XXE attempt),
 * or a missing required element.
 */
public class SamlMessageException extends RuntimeException {
    public SamlMessageException(String message) {
        super(message);
    }
}
