package tech.cwvermaak.weldforge.service;

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
import tech.cwvermaak.weldforge.config.tenant.PublicHostProperties;
import tech.cwvermaak.weldforge.config.tenant.TenantContext;
import tech.cwvermaak.weldforge.model.AuditEvent;
import tech.cwvermaak.weldforge.model.AuthProvider;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.model.dto.AuthResponseDto;
import tech.cwvermaak.weldforge.model.dto.LoginRequestDto;
import tech.cwvermaak.weldforge.model.dto.RegisterRequestDto;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.audit.AuditEventTypes;
import tech.cwvermaak.weldforge.service.audit.AuditService;
import tech.cwvermaak.weldforge.service.mfa.MfaService;
import tech.cwvermaak.weldforge.service.security.AccountLockedException;
import tech.cwvermaak.weldforge.service.security.AccountLockoutService;
import tech.cwvermaak.weldforge.service.security.PasswordPolicyService;
import tech.cwvermaak.weldforge.service.security.RefreshTokenService;
import tech.cwvermaak.weldforge.service.security.RefreshTokenService.Issued;

import java.util.Optional;
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
    private final tech.cwvermaak.weldforge.service.ldap.LdapUpstreamService ldapUpstreamService;
    private final tech.cwvermaak.weldforge.service.crm.CrmProvisioningService crmProvisioningService;
    private final PublicHostProperties publicHost;

    @Transactional
    public AuthResponseDto register(RegisterRequestDto request, HttpServletRequest httpRequest,
                                    HttpServletResponse response) {
        Tenant tenant = currentTenant();

        // Per-tenant feature flag: when registration is disabled the endpoint
        // should look like it doesn't exist. EntityNotFoundException is mapped
        // to 404 by GlobalExceptionHandler, matching how unknown tenants behave.
        if (Boolean.FALSE.equals(tenant.getRegistrationEnabled())) {
            throw new EntityNotFoundException("Registration is not available for this tenant");
        }

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

        // PRD DIR-01 / DIR-02: if the tenant has an enabled LDAP/AD
        // provider, try upstream authentication first. A success gets
        // the user provisioned locally and short-circuits past the
        // password compare. A failure (bad creds, user not in LDAP,
        // directory unreachable) falls through to the local path, so
        // break-glass admins always remain usable.
        Optional<User> ldapUser = ldapUpstreamService.authenticate(
                tenant, request.getIdentifier(), request.getPassword());
        if (ldapUser.isPresent()) {
            return completeLoginForUpstream(ldapUser.get(), tenant, httpRequest, response);
        }

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
        // PRD CRM-01: push the identity into every configured CRM. Safe
        // to run inline — the service catches all errors so a CRM outage
        // never rolls back a successful login.
        crmProvisioningService.provisionOnEvent(AuditEventTypes.AUTH_LOGIN_SUCCESS, user);
        return issueTokens(user, httpRequest, response);
    }

    /**
     * Shared completion path for upstream authentications (LDAP today,
     * SAML / OAuth2 could reuse it later). The upstream source has
     * already verified the credential so we skip the password compare
     * but keep every other gate: lockout, MFA challenge, MFA enrollment,
     * audit, metrics.
     */
    private AuthResponseDto completeLoginForUpstream(User user, Tenant tenant,
                                                      HttpServletRequest httpRequest,
                                                      HttpServletResponse response) {
        if (!user.isActive()) {
            meterRegistry.counter("sso.auth.login", "outcome", "failure", "tenant", tenant.getSlug()).increment();
            auditService.recordAnonymous(AuditEventTypes.AUTH_LOGIN_FAILED,
                    AuditEvent.Outcome.FAILURE, tenant.getId(),
                    user.getEmail(), AuditEventTypes.TARGET_USER,
                    String.valueOf(user.getId()),
                    AuditService.meta("reason", "user_inactive", "source", "ldap"));
            throw new BadCredentialsException("Invalid credentials");
        }
        try {
            lockoutService.ensureNotLocked(user);
        } catch (AccountLockedException locked) {
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
        if (mfaPolicyService.mustEnroll(user)) {
            String enrollmentToken = jwtService.generateMfaChallengeToken(
                    user.getId(), tenant.getId(), tenant.getSlug());
            auditService.recordUserAction(AuditEventTypes.MFA_ENROLLMENT_REQUIRED, user,
                    AuditEventTypes.TARGET_USER, String.valueOf(user.getId()),
                    AuditService.meta("reason", "tenant_policy_required", "source", "ldap"));
            return AuthResponseDto.builder()
                    .mustEnrollMfa(true)
                    .mfaChallengeToken(enrollmentToken)
                    .build();
        }
        meterRegistry.counter("sso.auth.login", "outcome", "success", "tenant", tenant.getSlug()).increment();
        auditService.recordUserAction(AuditEventTypes.AUTH_LOGIN_SUCCESS, user,
                AuditEventTypes.TARGET_USER, String.valueOf(user.getId()),
                AuditService.meta("source", "ldap"));
        crmProvisioningService.provisionOnEvent(AuditEventTypes.AUTH_LOGIN_SUCCESS, user);
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

        String refreshAdminRole = user.getAdminRole() != null ? user.getAdminRole().name() : "NONE";
        String accessToken = jwtService.generateAccessToken(
                user.getEmail(),
                tenant.getId(),
                tenant.getSlug(),
                user.isSuperAdmin(),
                user.getTokenVersion(),
                tenant.getAccessTtlMs(),
                tenant.getCustomClaims(),
                refreshAdminRole,
                tenantIssuer(tenant));
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

    /**
     * Self-service password change for the signed-in user. Verifies the
     * current password, validates the new one against the tenant policy,
     * then terminates every session: {@code token_version} is bumped
     * (invalidating outstanding access tokens) and all refresh-token
     * families are revoked. The user re-authenticates with the new
     * password — including in the tab they changed it from.
     */
    @Transactional
    public void changePassword(String email, String currentPassword, String newPassword) {
        Tenant tenant = currentTenant();
        User user = userRepository.findByTenant_SlugAndEmailIgnoreCase(tenant.getSlug(), email)
                .orElseThrow(() -> new EntityNotFoundException("User not found"));
        if (user.getPassword() == null
                || !passwordEncoder.matches(currentPassword, user.getPassword())) {
            auditService.recordUserAction(AuditEventTypes.AUTH_PASSWORD_CHANGE_FAILED, user,
                    AuditEventTypes.TARGET_USER, String.valueOf(user.getId()),
                    AuditService.meta("reason", "bad_current_password"));
            throw new BadCredentialsException("Current password is incorrect");
        }
        passwordPolicyService.validate(newPassword);
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setTokenVersion(user.getTokenVersion() + 1);
        userRepository.save(user);
        // A password change must not leave stolen sessions alive. Bumping
        // token_version kills outstanding access tokens; revoking every
        // refresh-token family kills the refresh side too. Without this an
        // attacker's stolen refresh token would simply outlive the very
        // password change meant to lock them out.
        int revoked = refreshTokenService.revokeAllForUser(user, "password_changed");
        auditService.recordUserAction(AuditEventTypes.AUTH_PASSWORD_CHANGED, user,
                AuditEventTypes.TARGET_USER, String.valueOf(user.getId()),
                AuditService.meta("refresh_tokens_revoked", revoked));
    }

    /**
     * Self-service profile update — name, email, cell phone. Email changes
     * flip {@code emailVerified} back to false so the user has to verify
     * the new address; phone changes do the same with {@code cellPhoneVerified}.
     */
    @Transactional
    public User updateMe(String email, String newName, String newEmail, String newCellPhone) {
        Tenant tenant = currentTenant();
        User user = userRepository.findByTenant_SlugAndEmailIgnoreCase(tenant.getSlug(), email)
                .orElseThrow(() -> new EntityNotFoundException("User not found"));

        if (newName != null && !newName.isBlank() && !newName.equals(user.getName())) {
            user.setName(newName.trim());
        }
        if (newEmail != null && !newEmail.isBlank()
                && !newEmail.trim().equalsIgnoreCase(user.getEmail())) {
            // Make sure the new email isn't already used in this tenant.
            userRepository.findByTenantIdAndEmailIgnoreCase(tenant.getId(), newEmail.trim())
                    .ifPresent(other -> {
                        if (!other.getId().equals(user.getId())) {
                            throw new IllegalArgumentException(
                                    "That email is already used by another account");
                        }
                    });
            user.setEmail(newEmail.trim());
            user.setEmailVerified(false);
        }
        if (newCellPhone != null && !newCellPhone.equals(user.getCellPhoneNumber())) {
            user.setCellPhoneNumber(newCellPhone.isBlank() ? null : newCellPhone.trim());
            user.setCellPhoneVerified(false);
        }
        userRepository.save(user);
        auditService.recordUserAction(AuditEventTypes.AUTH_PROFILE_UPDATED, user,
                AuditEventTypes.TARGET_USER, String.valueOf(user.getId()), null);
        return user;
    }

    // ---- internals ---------------------------------------------------

    /**
     * Canonical apex issuer URL for a tenant's access tokens. Matches the
     * {@code issuer} field of {@code /t/{slug}/.well-known/openid-configuration}
     * so RPs that strictly validate {@code iss} against discovery (e.g. the
     * Spring Security OAuth2 resource-server defaults) accept the token.
     */
    private String tenantIssuer(Tenant tenant) {
        if (tenant == null || tenant.getSlug() == null) return null;
        String origin = publicHost.originForTenant(null);
        return origin + "/t/" + tenant.getSlug();
    }

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
        // PRD SSO-03 + OA2-07 + ADM-02: per-tenant TTL, custom claims, admin role.
        String adminRoleName = user.getAdminRole() != null ? user.getAdminRole().name() : "NONE";
        String accessToken = jwtService.generateAccessToken(
                user.getEmail(),
                tenant.getId(),
                tenant.getSlug(),
                user.isSuperAdmin(),
                user.getTokenVersion(),
                tenant.getAccessTtlMs(),
                tenant.getCustomClaims(),
                adminRoleName,
                tenantIssuer(tenant));

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
        // Scope to the public base-domain so the cookie set on
        // {slug}.sso.weldforge.org is also sent when /api/auth/refresh runs
        // on the apex sso.weldforge.org (the SPA's /api proxy origin).
        String domain = publicHost.cookieDomain();
        if (domain != null) cookie.setDomain(domain);
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
                tech.cwvermaak.weldforge.config.JwtAuthenticationFilter.SESSION_COOKIE,
                accessToken);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        // SameSite=Lax so the cookie is sent on top-level redirects (the
        // OIDC /authorize flow lands here from a relying party). Strict
        // would block legitimate cross-site browser navigation.
        cookie.setAttribute("SameSite", "Lax");
        cookie.setPath("/");
        // Scope to the public base-domain so a session established on the
        // tenant subdomain ({slug}.sso.weldforge.org/login) is also sent on
        // the apex OIDC endpoint (sso.weldforge.org/t/{slug}/oauth2/...).
        // The JWT itself carries the tenant_id, so the cookie being
        // visible to other tenant subdomains carries no authentication
        // (JwtAuthenticationFilter rejects a mismatched tenant).
        String domain = publicHost.cookieDomain();
        if (domain != null) cookie.setDomain(domain);
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
