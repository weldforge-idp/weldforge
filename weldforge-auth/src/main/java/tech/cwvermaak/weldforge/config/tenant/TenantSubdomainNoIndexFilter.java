package tech.cwvermaak.weldforge.config.tenant;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Stamps {@code X-Robots-Tag: noindex, nofollow} onto every response served
 * from a tenant subdomain ({@code {slug}.<base-domain>}). Browser password
 * managers treat each subdomain as a distinct site — which is the goal —
 * but that distinctness only helps if search engines don't index every
 * tenant's login page as a duplicate of the apex form. The robots.txt
 * comment on the marketing site promises this; this filter enforces it.
 *
 * <p>Apex-host responses keep their normal indexability (the marketing
 * site and admin portal live there).</p>
 */
@Component
@RequiredArgsConstructor
@Order(Ordered.HIGHEST_PRECEDENCE + 20)
public class TenantSubdomainNoIndexFilter extends OncePerRequestFilter {

    private static final String HEADER = "X-Robots-Tag";
    private static final String VALUE  = "noindex, nofollow";

    private final PublicHostProperties publicHost;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        // Setting the header before delegating ensures it survives any
        // downstream response.reset() (which we do not currently call).
        // setHeader (not addHeader) so we never duplicate it.
        if (publicHost.slugFromHost(request.getServerName()) != null) {
            response.setHeader(HEADER, VALUE);
        }
        chain.doFilter(request, response);
    }
}
