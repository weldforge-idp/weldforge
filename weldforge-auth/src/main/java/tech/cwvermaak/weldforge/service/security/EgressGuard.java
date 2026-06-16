package tech.cwvermaak.weldforge.service.security;

import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;

/**
 * SSRF egress guard (B-LEGACY-1). Validates an admin-supplied outbound URL
 * (webhook target, CRM base URL) before WeldForge makes any request to it, so
 * the platform can't be used as a pivot to reach cloud-metadata endpoints
 * (169.254.169.254), loopback, or RFC-1918 / link-local services inside the VPC.
 *
 * <p>Checks: the scheme must be http/https; the host must resolve; and no
 * resolved address may be loopback, any-local, link-local (incl. the
 * 169.254.169.254 metadata IP), site-local (RFC 1918), unique-local IPv6
 * (fc00::/7), CGNAT (100.64.0.0/10), or multicast.
 *
 * <p><b>Residual:</b> validation resolves DNS, then the HTTP client resolves
 * again at request time — a DNS-rebinding (TOCTOU) window remains. Pinning the
 * validated IP into the request is tracked as a follow-up.
 */
public final class EgressGuard {

    private EgressGuard() {}

    /** Validate an outbound URL; returns the parsed URI or throws. */
    public static URI validate(String rawUrl) {
        if (rawUrl == null || rawUrl.isBlank()) {
            throw new EgressNotAllowedException("URL is required");
        }
        URI uri;
        try {
            uri = new URI(rawUrl.trim());
        } catch (URISyntaxException e) {
            throw new EgressNotAllowedException("malformed URL");
        }

        String scheme = uri.getScheme();
        if (scheme == null
                || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))) {
            throw new EgressNotAllowedException("only http/https URLs are allowed");
        }

        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            throw new EgressNotAllowedException("URL has no host");
        }
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1); // strip IPv6 literal brackets
        }

        InetAddress[] addresses;
        try {
            addresses = InetAddress.getAllByName(host);
        } catch (UnknownHostException e) {
            throw new EgressNotAllowedException("host does not resolve: " + host);
        }
        for (InetAddress addr : addresses) {
            if (isBlocked(addr)) {
                throw new EgressNotAllowedException(
                        "URL resolves to a disallowed internal address: " + addr.getHostAddress());
            }
        }
        return uri;
    }

    /** True if the address is in a range WeldForge must never reach outbound. */
    static boolean isBlocked(InetAddress a) {
        if (a.isAnyLocalAddress()      // 0.0.0.0, ::
                || a.isLoopbackAddress()   // 127.0.0.0/8, ::1
                || a.isLinkLocalAddress()  // 169.254.0.0/16 (incl. metadata), fe80::/10
                || a.isSiteLocalAddress()  // 10/8, 172.16/12, 192.168/16
                || a.isMulticastAddress()) {
                return true;
        }
        byte[] b = a.getAddress();
        if (b.length == 16 && (b[0] & 0xFE) == 0xFC) {
            return true; // IPv6 unique-local fc00::/7
        }
        if (b.length == 4 && (b[0] & 0xFF) == 100 && (b[1] & 0xC0) == 0x40) {
            return true; // IPv4 CGNAT 100.64.0.0/10
        }
        return false;
    }
}
