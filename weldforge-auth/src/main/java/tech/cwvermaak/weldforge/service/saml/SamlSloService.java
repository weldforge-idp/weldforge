package tech.cwvermaak.weldforge.service.saml;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import tech.cwvermaak.weldforge.model.SamlServiceProvider;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.SamlServiceProviderRepository;
import tech.cwvermaak.weldforge.service.audit.AuditEventTypes;
import tech.cwvermaak.weldforge.service.audit.AuditService;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

/**
 * SAML 2.0 Single Logout. Implements both directions:
 *
 * <ul>
 *   <li><b>IdP-initiated</b> — builds a {@code LogoutRequest} for each SP
 *       the user is signed into and hands it back to the controller to
 *       deliver (HTTP-POST or HTTP-Redirect binding).</li>
 *   <li><b>SP-initiated</b> — receives a {@code LogoutRequest} from an SP
 *       and builds a matching {@code LogoutResponse} with the user's
 *       session terminated on our side.</li>
 * </ul>
 *
 * PRD SAM-06: sync + async bindings — POST is "sync" (browser auto-submit
 * form), Redirect is "async" (deflate + base64url + query string).
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SamlSloService {

    public enum Binding { POST, REDIRECT }

    private final SamlServiceProviderRepository spRepository;
    private final AuditService auditService;
    /** Issuer rule shared with assertions (CONF-5.4). */
    private final SamlIdpService samlIdpService;
    private final tech.cwvermaak.weldforge.repository.RefreshTokenRepository refreshTokenRepository;
    private final tech.cwvermaak.weldforge.service.security.RefreshTokenFamilyRevoker familyRevoker;
    private final tech.cwvermaak.weldforge.service.AuthService authService;

    // ---- IdP-initiated: build LogoutRequest per SP -----------------

    /**
     * Build a SAML LogoutRequest XML and encode it for the requested
     * binding. POST → base64 raw XML. Redirect → DEFLATE compressed +
     * base64 (per SAML 2.0 HTTP-Redirect binding §3.4.4.1).
     */
    public String buildLogoutRequest(Tenant tenant, User user, SamlServiceProvider sp, Binding binding) {
        return buildLogoutRequest(tenant, user, sp, binding, null);
    }

    /**
     * As above, naming the session being ended (CONF-5.2) so the SP can end
     * its own session for that login rather than every session it holds for
     * the user.
     *
     * @param sessionId the login session, or null when unknown -- the request
     *                  then carries no SessionIndex, which an SP reads as
     *                  "every session for this principal"
     */
    public String buildLogoutRequest(Tenant tenant, User user, SamlServiceProvider sp, Binding binding,
                                     String sessionId) {
        String xml = buildLogoutRequestXml(tenant, user, sp, sessionId);
        return encode(xml, binding);
    }

    /** Back-compat overload — defaults to POST binding (base64 raw). */
    public String buildLogoutRequest(Tenant tenant, User user, SamlServiceProvider sp) {
        return buildLogoutRequest(tenant, user, sp, Binding.POST);
    }

    private String buildLogoutRequestXml(Tenant tenant, User user, SamlServiceProvider sp,
                                         String sessionId) {
        String issuer = samlIdpService.issuerFor(tenant, sp);
        String requestId = "_" + UUID.randomUUID();
        Instant now = Instant.now();
        String nameId = SamlIdpService.resolveNameId(user, sp.getNameIdFormat());

        StringBuilder xml = new StringBuilder();
        xml.append("<samlp:LogoutRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"");
        xml.append(" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"");
        xml.append(" ID=\"").append(requestId).append("\"");
        xml.append(" Version=\"2.0\"");
        xml.append(" IssueInstant=\"").append(now.toString()).append("\"");
        xml.append(" Destination=\"").append(escapeXml(sp.getSloUrl())).append("\"");
        xml.append(">\n");

        xml.append("  <saml:Issuer>").append(escapeXml(issuer)).append("</saml:Issuer>\n");

        xml.append("  <saml:NameID Format=\"").append(escapeXml(sp.getNameIdFormat())).append("\">");
        xml.append(escapeXml(nameId));
        xml.append("</saml:NameID>\n");
        // Schema order: SessionIndex follows NameID.
        if (sessionId != null && !sessionId.isBlank()) {
            xml.append("  <samlp:SessionIndex>")
               .append(escapeXml(SamlIdpService.sessionIndexFor(sessionId, sp)))
               .append("</samlp:SessionIndex>\n");
        }

        xml.append("</samlp:LogoutRequest>");
        return xml.toString();
    }

    /**
     * Fan-out IdP-initiated logout across every SP with a SLO URL. The
     * controller decides how to deliver each payload based on its binding.
     */
    public List<SloPayload> initiateLogout(Tenant tenant, User user) {
        return initiateLogout(tenant, user, Binding.POST);
    }

    public List<SloPayload> initiateLogout(Tenant tenant, User user, Binding binding) {
        return initiateLogout(tenant, user, binding, null);
    }

    /** As above, with each LogoutRequest naming the session being ended. */
    public List<SloPayload> initiateLogout(Tenant tenant, User user, Binding binding, String sessionId) {
        List<SamlServiceProvider> sps = spRepository.findByTenantIdAndEnabledTrue(tenant.getId());
        List<SloPayload> payloads = new ArrayList<>();

        for (SamlServiceProvider sp : sps) {
            if (sp.getSloUrl() == null || sp.getSloUrl().isBlank()) {
                log.debug("SP {} has no SLO URL — skipping", sp.getEntityId());
                continue;
            }
            String encoded = buildLogoutRequest(tenant, user, sp, binding, sessionId);
            payloads.add(new SloPayload(
                    sp.getId(),
                    sp.getEntityId(),
                    sp.getName(),
                    sp.getSloUrl(),
                    encoded,
                    binding
            ));
            log.info("Built LogoutRequest for SP {} (entity_id={}, binding={})",
                    sp.getName(), sp.getEntityId(), binding);
        }

        auditService.recordUserAction(AuditEventTypes.SAML_IDP_LOGOUT_INITIATED, user,
                AuditEventTypes.TARGET_USER, String.valueOf(user.getId()),
                AuditService.meta(
                        "tenant_slug", tenant.getSlug(),
                        "sp_count", payloads.size(),
                        "binding", binding.name()));

        return payloads;
    }

    // ---- SP-initiated: handle incoming LogoutRequest ---------------

    /**
     * What an SP-initiated logout actually ended on our side.
     *
     * @param sessionsEnded how many named sessions matched; 0 when {@code allSessions}
     */
    public record LogoutOutcome(int sessionsEnded, boolean allSessions, boolean currentSessionEnded) {}

    /**
     * End the sessions an SP's LogoutRequest names (CONF-5.2).
     *
     * <p>Until this existed the endpoint answered every LogoutRequest with
     * {@code Success} and ended nothing -- the user was still signed in to
     * WeldForge, and to every other SP, after "signing out". SAML Core
     * §3.7.3.2 gives the two cases:
     *
     * <ul>
     *   <li><b>SessionIndex present:</b> end only the sessions it names. Each
     *       live login session of this user is hashed for this SP the same way
     *       the assertion's index was, and matches are revoked. The user's
     *       other sessions -- another browser, a phone -- are untouched,
     *       which is the whole point of naming a session.</li>
     *   <li><b>No SessionIndex:</b> every session of the principal ends.</li>
     * </ul>
     *
     * <p>Matching only ever considers the calling user's own sessions, so a
     * SessionIndex can never be used to end somebody else's.
     *
     * @param currentSessionId the session presenting this request, so the
     *                         caller can clear its cookies if it just ended
     */
    @org.springframework.transaction.annotation.Transactional
    public LogoutOutcome terminateSessions(Tenant tenant, SamlServiceProvider sp, User user,
                                           List<String> sessionIndexes, String currentSessionId) {
        LogoutOutcome outcome;
        if (sessionIndexes == null || sessionIndexes.isEmpty()) {
            authService.logoutAll(user);
            outcome = new LogoutOutcome(0, true, true);
        } else {
            Set<String> named = Set.copyOf(sessionIndexes);
            Set<UUID> ended = new LinkedHashSet<>();
            for (var row : refreshTokenRepository.findByUserIdAndRevokedAtIsNull(user.getId())) {
                UUID family = row.getFamilyId();
                if (!ended.contains(family)
                        && named.contains(SamlIdpService.sessionIndexFor(family.toString(), sp))) {
                    familyRevoker.revoke(family, "saml_slo");
                    ended.add(family);
                }
            }
            boolean current = currentSessionId != null
                    && ended.stream().anyMatch(f -> f.toString().equals(currentSessionId));
            outcome = new LogoutOutcome(ended.size(), false, current);
        }

        auditService.recordUserAction(AuditEventTypes.SAML_SP_LOGOUT, user,
                AuditEventTypes.TARGET_SAML_SP, String.valueOf(sp.getId()),
                AuditService.meta(
                        "sp_entity_id", sp.getEntityId(),
                        "session_indexes", sessionIndexes == null ? 0 : sessionIndexes.size(),
                        "sessions_ended", outcome.allSessions() ? "all" : outcome.sessionsEnded()));
        return outcome;
    }

    /**
     * Build a LogoutResponse for an SP-initiated LogoutRequest. The
     * response echoes the request ID in {@code InResponseTo} and reports
     * {@code urn:oasis:names:tc:SAML:2.0:status:Success}.
     *
     * Returns the response encoded for the given binding, ready for the
     * controller to deliver via redirect or auto-submit form.
     */
    public String buildLogoutResponse(Tenant tenant, SamlServiceProvider sp,
                                       String inResponseTo, Binding binding) {
        return buildLogoutResponse(tenant, sp, inResponseTo, binding, STATUS_SUCCESS);
    }

    public static final String STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
    /** The request was wrong on the sender's side -- here, a NameID that is not the caller. */
    public static final String STATUS_REQUESTER = "urn:oasis:names:tc:SAML:2.0:status:Requester";

    /** As above, reporting {@code statusCode} rather than assuming success. */
    public String buildLogoutResponse(Tenant tenant, SamlServiceProvider sp,
                                      String inResponseTo, Binding binding, String statusCode) {
        String issuer = samlIdpService.issuerFor(tenant, sp);
        String responseId = "_" + UUID.randomUUID();
        Instant now = Instant.now();

        StringBuilder xml = new StringBuilder();
        xml.append("<samlp:LogoutResponse xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"");
        xml.append(" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"");
        xml.append(" ID=\"").append(responseId).append("\"");
        xml.append(" Version=\"2.0\"");
        xml.append(" IssueInstant=\"").append(now.toString()).append("\"");
        xml.append(" Destination=\"").append(escapeXml(sp.getSloUrl())).append("\"");
        if (inResponseTo != null && !inResponseTo.isBlank()) {
            xml.append(" InResponseTo=\"").append(escapeXml(inResponseTo)).append("\"");
        }
        xml.append(">\n");
        xml.append("  <saml:Issuer>").append(escapeXml(issuer)).append("</saml:Issuer>\n");
        xml.append("  <samlp:Status><samlp:StatusCode Value=\"").append(escapeXml(statusCode))
           .append("\"/></samlp:Status>\n");
        xml.append("</samlp:LogoutResponse>");

        return encode(xml.toString(), binding);
    }

    // ---- Encoding --------------------------------------------------

    /**
     * Encode a SAML message for the given binding.
     * POST: plain base64 (no compression, browser auto-submits the form).
     * REDIRECT: DEFLATE raw (no zlib wrapper) then base64, per the spec.
     */
    private static String encode(String xml, Binding binding) {
        byte[] raw = xml.getBytes(StandardCharsets.UTF_8);
        if (binding == Binding.REDIRECT) {
            try {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                Deflater def = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
                try (DeflaterOutputStream dos = new DeflaterOutputStream(baos, def)) {
                    dos.write(raw);
                }
                return Base64.getEncoder().encodeToString(baos.toByteArray());
            } catch (Exception e) {
                throw new IllegalStateException("Failed to deflate SAML message", e);
            }
        }
        return Base64.getEncoder().encodeToString(raw);
    }

    // ---- Types -----------------------------------------------------

    public record SloPayload(
            Long spId,
            String entityId,
            String spName,
            String sloUrl,
            String logoutRequest,
            Binding binding
    ) {}

    // ---- XML helpers ----------------------------------------------

    private static String escapeXml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&apos;");
    }
}
