package tech.cwvermaak.weldforge.service.security;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.ConsumptionProbe;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Function;

/**
 * Per-IP token bucket rate limiter. Three buckets — login, register, mfa-verify
 * — each with independent capacity and refill cadence so we can tune aggressively
 * on the hot endpoints without starving legitimate traffic to the others.
 *
 * The store is in-memory ({@link ConcurrentHashMap}) which is fine for a single
 * node. For a multi-instance deployment the same API can be backed by a shared
 * bucket4j-redis without changes to the callers.
 */
@Service
@RequiredArgsConstructor
public class RateLimitingService {

    public enum Bucket4jEndpoint { LOGIN, REGISTER, MFA_VERIFY, RECOVERY }

    private final RateLimitProperties properties;

    private final ConcurrentMap<String, Bucket> loginBuckets    = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Bucket> registerBuckets = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Bucket> mfaBuckets      = new ConcurrentHashMap<>();
    // B-AUTH-3: dedicated bucket for account-recovery + SMS-send endpoints
    // (password reset, email re-verification, SMS OTP send), keyed per IP. Uses
    // the register cadence (low-frequency, sensitive) without a separate config.
    private final ConcurrentMap<String, Bucket> recoveryBuckets = new ConcurrentHashMap<>();

    /**
     * Try to consume one token from the caller's bucket.
     *
     * @return a probe whose {@code isConsumed()} tells you whether to allow
     *         the request, and whose {@code getNanosToWaitForRefill()} maps
     *         to a {@code Retry-After} header if you reject it.
     */
    public ConsumptionProbe tryConsume(Bucket4jEndpoint endpoint, String key) {
        if (!properties.isEnabled()) {
            // When disabled we return a synthetic "always allowed" probe so
            // callers don't need to branch on the flag.
            return ConsumptionProbe.consumed(Long.MAX_VALUE, 0L);
        }
        Bucket bucket = resolve(endpoint).apply(key);
        return bucket.tryConsumeAndReturnRemaining(1);
    }

    private Function<String, Bucket> resolve(Bucket4jEndpoint endpoint) {
        return switch (endpoint) {
            case LOGIN      -> key -> loginBuckets.computeIfAbsent(key, k -> newLoginBucket());
            case REGISTER   -> key -> registerBuckets.computeIfAbsent(key, k -> newRegisterBucket());
            case MFA_VERIFY -> key -> mfaBuckets.computeIfAbsent(key, k -> newMfaBucket());
            case RECOVERY   -> key -> recoveryBuckets.computeIfAbsent(key, k -> newRecoveryBucket());
        };
    }

    private Bucket newRecoveryBucket() {
        return Bucket.builder()
                .addLimit(Bandwidth.builder()
                        .capacity(properties.getRegisterCapacity())
                        .refillIntervally(properties.getRegisterCapacity(),
                                Duration.ofMinutes(properties.getRegisterRefillMinutes()))
                        .build())
                .build();
    }

    private Bucket newLoginBucket() {
        return Bucket.builder()
                .addLimit(Bandwidth.builder()
                        .capacity(properties.getLoginCapacity())
                        .refillIntervally(properties.getLoginCapacity(),
                                Duration.ofMinutes(properties.getLoginRefillMinutes()))
                        .build())
                .build();
    }

    private Bucket newRegisterBucket() {
        return Bucket.builder()
                .addLimit(Bandwidth.builder()
                        .capacity(properties.getRegisterCapacity())
                        .refillIntervally(properties.getRegisterCapacity(),
                                Duration.ofMinutes(properties.getRegisterRefillMinutes()))
                        .build())
                .build();
    }

    private Bucket newMfaBucket() {
        return Bucket.builder()
                .addLimit(Bandwidth.builder()
                        .capacity(properties.getMfaVerifyCapacity())
                        .refillIntervally(properties.getMfaVerifyCapacity(),
                                Duration.ofMinutes(properties.getMfaVerifyRefillMinutes()))
                        .build())
                .build();
    }
}
