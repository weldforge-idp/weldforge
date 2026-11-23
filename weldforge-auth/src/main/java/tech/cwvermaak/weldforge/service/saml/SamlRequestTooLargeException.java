package tech.cwvermaak.weldforge.service.saml;

/**
 * An inbound SAML message inflated past the allowed ceiling (WF-13) — a
 * decompression bomb. Thrown by {@link SamlDeflate}, surfaced by the IdP
 * controller as a {@code 400 Bad Request}.
 */
public class SamlRequestTooLargeException extends RuntimeException {
    public SamlRequestTooLargeException(String message) {
        super(message);
    }
}
