package tech.cwvermaak.weldforge.service.resilience;

/**
 * Thrown when a downstream dependency is quarantined by its circuit
 * breaker (PRD AVL-04). Tagged with the provider name so callers and the
 * global exception handler can surface a clear "X is temporarily
 * unavailable" error instead of leaking the resilience4j type.
 */
public class ProviderUnavailableException extends RuntimeException {

    private final String provider;

    public ProviderUnavailableException(String provider, String message, Throwable cause) {
        super(message, cause);
        this.provider = provider;
    }

    public ProviderUnavailableException(String provider, String message) {
        this(provider, message, null);
    }

    public String getProvider() {
        return provider;
    }
}
