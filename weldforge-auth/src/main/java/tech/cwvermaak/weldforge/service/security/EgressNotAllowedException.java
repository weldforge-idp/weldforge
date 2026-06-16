package tech.cwvermaak.weldforge.service.security;

/**
 * Thrown when an outbound URL (webhook target, CRM base URL) is rejected by the
 * {@link EgressGuard} — a non-http(s) scheme, an unresolvable host, or a host
 * that resolves to an internal / loopback / link-local / metadata address.
 */
public class EgressNotAllowedException extends RuntimeException {
    public EgressNotAllowedException(String message) {
        super(message);
    }
}
