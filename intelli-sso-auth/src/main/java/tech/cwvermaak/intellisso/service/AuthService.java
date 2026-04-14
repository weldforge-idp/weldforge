package tech.cwvermaak.intellisso.service;

import io.micrometer.core.instrument.MeterRegistry;
import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.intellisso.config.tenant.TenantContext;
import tech.cwvermaak.intellisso.model.AuditEvent;
import tech.cwvermaak.intellisso.model.AuthProvider;
import tech.cwvermaak.intellisso.model.Tenant;
import tech.cwvermaak.intellisso.model.User;
import tech.cwvermaak.intellisso.model.dto.AuthResponseDto;
import tech.cwvermaak.intellisso.model.dto.LoginRequestDto;
import tech.cwvermaak.intellisso.model.dto.RegisterRequestDto;
import tech.cwvermaak.intellisso.repository.TenantRepository;
import tech.cwvermaak.intellisso.repository.UserRepository;
import tech.cwvermaak.intellisso.service.audit.AuditEventTypes;
import tech.cwvermaak.intellisso.service.audit.AuditService;
import tech.cwvermaak.intellisso.service.mfa.MfaService;
import tech.cwvermaak.intellisso.service.security.AccountLockedException;
import tech.cwvermaak.intellisso.service.security.AccountLockoutService;
import tech.cwvermaak.intellisso.service.security.PasswordPolicyService;
import tech.cwvermaak.intellisso.service.security.RefreshTokenService;
import tech.cwvermaak.intellisso.service.security.RefreshTokenService.Issued;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class AuthService {

    public static final String REFRESH_COOKIE = "refresh_token";

    private final UserRepository userRepository;
    private final TenantRepository tenantRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final MfaService mfaService;
    private final AuditService auditService;
    private final AccountLockoutService lockoutService;
    private final PasswordPolicyService passwordPolicyService;
    private final RefreshTokenService refreshTokenService;
    private final EmailVerificationService emailVerificationService;
    private final TenantMfaPolicyService mfaPolicyService;
    private final MeterRegistry meterRegistry;

    @Transactional
    public AuthResponseDto register(RegisterRequestDto request, HttpServletRequest httpRequest,
                                    HttpServletResponse response) {
        Tenant tenant = currentTenant();

        // Pre-check password policy before we allocate a user row.
        passwordPolicyService.validate(request.getPassword());

        if (userRepository.findByTenantIdAndEmailIgnoreCase(tenant.getId(), request.getEmail()).isPresent()) {
            throw new IllegalArgumentException("Email already in use for this tenant");
        }
        if (userRepository.findByTenantIdAndUsernameIgnoreCase(tenant.getId(), request.getName()).isPresent()) {
            throw new IllegalArgumentException("Username already in use for this tenant");
        }

        User user = User.builder()
                .tenant(tenant)
                .username(request.getName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .provider(AuthProvider.LOCAL)
                .providerId("local")
                .build();

        userRepository.save(user);
        auditService.recordUserAction(AuditEventTypes.AUTH_REGISTER, user,
                AuditEventTypes.TARGET_USER, String.valueOf(user.getId()),
                AuditService.meta("provider", "LOCAL"));
        emailVerificationService.sendVerification(user);
        return issueTokens(user, httpRequest, response);
    }

    @Transactional
    public AuthResponseDto login(LoginRequestDto request, HttpServletRequest httpRequest,
                                 HttpServletResponse response) {
        Tenant tenant = currentTenant();

        User user = userRepository.findByTenantAndIdentifier(tenant.getId(), request.getIdentifier())
                .orElse(null);

        if (user == null) {
            meterRegistry.counter("sso.auth.login", "outcome", "failure", "tenant", tenant.getSlug()).increment();
            auditService.recordAnonymous(AuditEventTypes.AUTH_LOGIN_FAILED,
                    AuditEvent.Outcome.FAILURE, tenant.getId(),
                    request.getIdentifier(), AuditEventTypes.TARGET_USER, null,
                    AuditService.meta("reason", "unknown_user"));
            throw new BadCredentialsException("Invalid credentials");
        }

        // SCIM deactivation — Okta/Workday/Entra can flip this off when a
        // person leaves the org. We give the same vague "Invalid
        // credentials" outward to avoid leaking which accounts have been
        // disabled, but the audit log carries the real reason.
        if (!user.isActive()) {
            meterRegistry.counter("sso.auth.login", "outcome", "failure", "tenant", tenant.getSlug()).increment();
            auditService.recordAnonymous(AuditEventTypes.AUTH_LOGIN_FAILED,
                    AuditEvent.Outcome.FAILURE, tenant.getId(),
                    request.getIdentifier(), AuditEventTypes.TARGET_USER,
                    String.valueOf(user.getId()),
                    AuditService.meta("reason", "user_inactive"));
            throw new BadCredentialsException("Invalid credentials");
        }

        // Locked accounts never reach the password compare — this prevents
        // timing oracles based on bcrypt runtime.
        try {
            lockoutService.ensureNotLocked(user);
        } catch (AccountLockedException locked) {
            // Present an identical "invalid credentials" error outward so an
            // attacker can't distinguish locked from non-existent.
            throw new BadCredentialsException("Invalid credentials");
        }

        if (user.getPassword() == null
                || !passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            lockoutService.recordFailure(user);
            meterRegistry.counter("sso.auth.login", "outcome", "failure", "tenant", tenant.getSlug()).increment();
            auditService.recordAnonymous(AuditEventTypes.AUTH_LOGIN_FAILED,
                    AuditEvent.Outcome.FAILURE, tenant.getId(),
                    request.getIdentifier(), AuditEventTypes.TARGET_USER,
                    String.valueOf(user.getId()),
                    AuditService.meta("reason", "bad_password"));
            throw new BadCredentialsException("Invalid credentials");
        }

        lockoutService.recordSuccess(user);

        if (mfaService.hasVerifiedFactor(user)) {
            String challengeToken = jwtService.generateMfaChallengeToken(
                    user.getId(), tenant.getId(), tenant.getSlug());
            auditService.recordUserAction(AuditEventTypes.AUTH_LOGIN_MFA_REQUIRED, user,
                    AuditEventTypes.TARGET_USER, String.valueOf(user.getId()), null);
            return AuthResponseDto.builder()
                    .mfaRequired(true)
                    .mfaChallengeToken(challengeToken)
                    .availableFactors(mfaService.availableFactors(user))
                    .build();
        }

        // PRD MFA-03: if the tenant policy is REQUIRED and the user has no
        // verified factor (and grace period has elapsed), force enrollment
        // instead of issuing a token.
        if (mfaPolicyService.mustEnroll(user)) {
            String enrollmentToken = jwtService.generateMfaChallengeToken(
                    user.getId(), tenant.getId(), tenant.getSlug());
            auditService.recordUserAction(AuditEventTypes.MFA_ENROLLMENT_REQUIRED, user,
                    AuditEventTypes.TARGET_USER, String.valueOf(user.getId()),
                    AuditService.meta("reason", "tenant_policy_required"));
            return AuthResponseDto.builder()
                    .mustEnrollMfa(true)
                    .mfaChallengeToken(enrollmentToken)
                    .build();
        }

        meterRegistry.counter("sso.auth.login", "outcome", "success", "tenant", tenant.getSlug()).increment();
        auditService.recordUserAction(AuditEventTypes.AUTH_LOGIN_SUCCESS, user,
                AuditEventTypes.TARGET_USER, String.valueOf(user.getId()), null);
        return issueTokens(user, httpRequest, response);
    }

    public AuthResponseDto completeMfaLogin(User user, HttpServletRequest httpRequest,
                                            HttpServletResponse response) {
        auditService.recordUserAction(AuditEventTypes.MFA_CHALLENGE_SUCCESS, user,
                AuditEventTypes.TARGET_USER, String.valueOf(user.getId()), null);
        auditService.recordUserAction(AuditEventTypes.AUTH_LOGIN_SUCCESS, user,
                AuditEventTypes.TARGET_USER, String.valueOf(user.getId()),
                AuditService.meta("mfa", true));
        return issueTokens(user, httpRequest, response);
    }

    /** Exchange a refresh token cookie for a fresh access token (rotating the refresh token). */
    @Transactional
    public AuthResponseDto refresh(HttpServletRequest request, HttpServletResponse response) {
        String raw = readRefreshCookie(request);
        Issued issued = refreshTokenService.rotate(raw, clientIp(request), userAgent(request));
        User user = issued.row().getUser();
        Tenant tenant = user.getTenant();
        writeRefreshCookie(response, issued.rawToken(), tenant.getRefreshTtlMs());

        String accessToken = jwtService.generateAccessToken(
                user.getEmail(),
                tenant.getId(),
                tenant.getSlug(),
                user.isSuperAdmin(),
                user.getTokenVersion(),
                tenant.getAccessTtlMs(),
                tenant.getCustomClaims());
        long effectiveTtl = tenant.getAccessTtlMs() != null
                ? tenant.getAccessTtlMs() / 1000
                : jwtService.getExpirationTime();
        return AuthResponseDto.builder()
                .token(accessToken)
                .expiresIn(effectiveTtl)
                .build();
    }

    /**
     * Invalidate every session for the user — refresh-token families are
     * revoked and the user's {@code token_version} is bumped so outstanding
     * access tokens stop working on their next request.
     */
    @Transactional
    public int logoutAll(User user) {
        int refreshCount = refreshTokenService.revokeAllForUser(user, "user_logout_all");
        user.setTokenVersion(user.getTokenVersion() + 1);
        userRepository.save(user);
        auditService.recordUserAction("auth.session.revoked_all", user,
                AuditEventTypes.TARGET_USER, String.valueOf(user.getId()),
                AuditService.meta("refresh_tokens_revoked", refreshCount));
        return refreshCount;
    }

    public String issueEnrollmentCeremonyKey(User user) {
        return "enroll-" + user.getId() + "-" + UUID.randomUUID();
    }

    // ---- internals ---------------------------------------------------

    private Tenant currentTenant() {
        String slug = TenantContext.get();
        if (slug == null || slug.isBlank()) {
            throw new IllegalStateException("No tenant in request context");
        }
        return tenantRepository.findBySlug(slug)
                .orElseThrow(() -> new EntityNotFoundException("Unknown tenant: " + slug));
    }

    private AuthResponseDto issueTokens(User user, HttpServletRequest httpRequest,
                                        HttpServletResponse response) {
        Tenant tenant = user.getTenant();
        // PRD SSO-03 + OA2-07: honor per-tenant TTL and custom claims.
        String accessToken = jwtService.generateAccessToken(
                user.getEmail(),
                tenant.getId(),
                tenant.getSlug(),
                user.isSuperAdmin(),
                user.getTokenVersion(),
                tenant.getAccessTtlMs(),
                tenant.getCustomClaims());

        Issued refresh = refreshTokenService.issueNew(user, clientIp(httpRequest), userAgent(httpRequest));
        writeRefreshCookie(response, refresh.rawToken(), tenant.getRefreshTtlMs());

        // Also set the access token as an HttpOnly cookie so server-side
        // browser-redirect flows (like OIDC /authorize) can authenticate
        // the caller without the SPA needing to forward the JWT manually.
        // The Angular code still gets the token in the response body.
        writeSessionCookie(response, accessToken, tenant.getAccessTtlMs());

        long effectiveTtl = tenant.getAccessTtlMs() != null
                ? tenant.getAccessTtlMs() / 1000
                : jwtService.getExpirationTime();
        return AuthResponseDto.builder()
                .token(accessToken)
                .expiresIn(effectiveTtl)
                .mfaRequired(false)
                .build();
    }

    private void writeRefreshCookie(HttpServletResponse response, String rawToken) {
        writeRefreshCookie(response, rawToken, null);
    }

    private void writeRefreshCookie(HttpServletResponse response, String rawToken, Long tenantRefreshTtlMs) {
        Cookie cookie = new Cookie(REFRESH_COOKIE, rawToken);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setPath("/api/auth");
        long ttlSeconds = tenantRefreshTtlMs != null && tenantRefreshTtlMs > 0
                ? tenantRefreshTtlMs / 1000
                : jwtService.getRefreshTokenExpirationTime();
        cookie.setMaxAge((int) ttlSeconds);
        response.addCookie(cookie);
    }

    private void writeSessionCookie(HttpServletResponse response, String accessToken) {
        writeSessionCookie(response, accessToken, null);
    }

    private void writeSessionCookie(HttpServletResponse response, String accessToken, Long tenantAccessTtlMs) {
        Cookie cookie = new Cookie(
                tech.cwvermaak.intellisso.config.JwtAuthenticationFilter.SESSION_COOKIE,
                accessToken);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        // SameSite=Lax so the cookie is sent on top-level redirects (the
        // OIDC /authorize flow lands here from a relying party). Strict
        // would block legitimate cross-site browser navigation.
        cookie.setAttribute("SameSite", "Lax");
        cookie.setPath("/");
        long ttlSeconds = tenantAccessTtlMs != null && tenantAccessTtlMs > 0
                ? tenantAccessTtlMs / 1000
                : jwtService.getExpirationTime();
        cookie.setMaxAge((int) ttlSeconds);
        response.addCookie(cookie);
    }

    private static String readRefreshCookie(HttpServletRequest request) {
        if (request.getCookies() == null) return null;
        for (Cookie c : request.getCookies()) {
            if (REFRESH_COOKIE.equals(c.getName())) return c.getValue();
        }
        return null;
    }

    private static String clientIp(HttpServletRequest request) {
        if (request == null) return null;
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            int comma = forwarded.indexOf(',');
            return (comma == -1 ? forwarded : forwarded.substring(0, comma)).trim();
        }
        return request.getRemoteAddr();
    }

    private static String userAgent(HttpServletRequest request) {
        if (request == null) return null;
        String ua = request.getHeader("User-Agent");
        if (ua == null) return null;
        return ua.length() > 512 ? ua.substring(0, 512) : ua;
    }
}
