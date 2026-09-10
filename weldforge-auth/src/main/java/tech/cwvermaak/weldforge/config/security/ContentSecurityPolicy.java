package tech.cwvermaak.weldforge.config.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.header.HeaderWriter;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * {@code Content-Security-Policy} on every response, with a per-request nonce
 * for the server-rendered pages (CONF-7.2).
 *
 * <p>The pages this protects are few but matter: the OIDC consent screen, the
 * SAML auto-submit form, the tenant verification page and the hosted login
 * pages. They are hand-built HTML on an authenticated origin -- the consent
 * screen in particular holds an Allow button and a CSRF token -- so an
 * injected script there could read or drive the decision. The policy allows
 * only same-origin resources and the inline {@code <style>}/{@code <script>}
 * blocks carrying this request's nonce, which an injection cannot know.
 *
 * <p>What it deliberately leaves out: {@code form-action}. The consent form
 * posts to us and we answer with a redirect to the relying party, and the SAML
 * form posts straight to the SP's ACS URL; browsers apply {@code form-action}
 * to that whole chain, so constraining it would break both flows.
 *
 * <p>Pages read their nonce with {@link #nonce()} while rendering; the header
 * is written when the response commits and reads the same request attribute,
 * so the two always agree.
 */
public final class ContentSecurityPolicy implements HeaderWriter {

    public static final String HEADER = "Content-Security-Policy";
    static final String NONCE_ATTRIBUTE = ContentSecurityPolicy.class.getName() + ".nonce";

    private static final SecureRandom RNG = new SecureRandom();

    /** This request's nonce, minted on first use. */
    public static String nonce(HttpServletRequest request) {
        Object existing = request.getAttribute(NONCE_ATTRIBUTE);
        if (existing instanceof String s) return s;
        byte[] bytes = new byte[18];
        RNG.nextBytes(bytes);
        String nonce = Base64.getEncoder().encodeToString(bytes);
        request.setAttribute(NONCE_ATTRIBUTE, nonce);
        return nonce;
    }

    /** The current request's nonce, or null outside a request (e.g. a unit test). */
    public static String nonce() {
        if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attrs) {
            return nonce(attrs.getRequest());
        }
        return null;
    }

    /** {@code " nonce=\"…\""} for an inline element, or empty outside a request. */
    public static String nonceAttribute() {
        String n = nonce();
        return n == null ? "" : " nonce=\"" + n + "\"";
    }

    @Override
    public void writeHeaders(HttpServletRequest request, HttpServletResponse response) {
        if (response.containsHeader(HEADER)) return;
        response.setHeader(HEADER, policy(request.getRequestURI(), nonce(request)));
    }

    static String policy(String path, String nonce) {
        // Swagger UI (dev tooling; not routed publicly) sets inline styles
        // from script, which no nonce can cover.
        String styleSrc = path != null && path.startsWith("/swagger-ui")
                ? "'self' 'unsafe-inline'"
                : "'self' 'nonce-" + nonce + "' https://fonts.googleapis.com";
        return "default-src 'self'; "
                + "script-src 'self' 'nonce-" + nonce + "'; "
                + "style-src " + styleSrc + "; "
                // The hosted login's display face.
                + "font-src 'self' https://fonts.gstatic.com; "
                // Tenant logos are arbitrary HTTPS URLs by design.
                + "img-src 'self' https: data:; "
                + "object-src 'none'; "
                + "base-uri 'none'; "
                + "frame-ancestors 'none'";
    }
}
