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
 * <p><strong>The store is in-memory ({@link ConcurrentHashMap}), so every
 * instance counts separately.</strong> That is not a detail — it means the
 * effective limit is the configured limit multiplied by the replica count. Two
 * replicas and a login limit of 10/15min is really 20/15min to an attacker who
 * is load-balanced across both, and the operator who configured 10 has no way
 * to see that from the configuration.
 *
 * <p>This is the one thing that does not simply scale out. Before raising
 * replicas, either divide the configured limits by the replica count, or move
 * these buckets onto the cluster's Redis with {@code bucket4j-redis} — the
 * caller-facing API here does not change either way. The scheduled jobs were
 * the other obstacle and are already handled, by ShedLock.
 *
 * <p>What does <em>not</em> weaken with replicas: account lockout, which counts
 * failures in the database, and is the control that actually stops a
 * credential-stuffing run. Rate limiting is the cheap first line, not the last.
 *
 * @see tech.cwvermaak.weldforge.config.SchedulerLockConfig
 */
@Service
@RequiredArgsConstructor
public class RateLimitingService {

    public enum Bucket4jEndpoint { LOGIN, REGISTER, MFA_VERIFY, RECOVERY, PUBLIC_ORDER }

    private final RateLimitProperties properties;

    private final ConcurrentMap<String, Bucket> loginBuckets    = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Bucket> registerBuckets = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Bucket> mfaBuckets      = new ConcurrentHashMap<>();
    // B-AUTH-3: dedicated bucket for account-recovery + SMS-send endpoints
    // (password reset, email re-verification, SMS OTP send), keyed per IP. Uses
    // the register cadence (low-frequency, sensitive) without a separate config.
    private final ConcurrentMap<String, Bucket> recoveryBuckets = new ConcurrentHashMap<>();
    // The anonymous order funnel writes a pending_orders row and opens a
    // payment-gateway checkout per call: its own bucket, register cadence, so
    // an order and a sign-up from the same office do not starve each other.
    private final ConcurrentMap<String, Bucket> orderBuckets    = new ConcurrentHashMap<>();

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
            case PUBLIC_ORDER -> key -> orderBuckets.computeIfAbsent(key, k -> newRecoveryBucket());
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
