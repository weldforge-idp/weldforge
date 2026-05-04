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

    // ---- IdP-initiated: build LogoutRequest per SP -----------------

    /**
     * Build a SAML LogoutRequest XML and encode it for the requested
     * binding. POST → base64 raw XML. Redirect → DEFLATE compressed +
     * base64 (per SAML 2.0 HTTP-Redirect binding §3.4.4.1).
     */
    public String buildLogoutRequest(Tenant tenant, User user, SamlServiceProvider sp, Binding binding) {
        String xml = buildLogoutRequestXml(tenant, user, sp);
        return encode(xml, binding);
    }

    /** Back-compat overload — defaults to POST binding (base64 raw). */
    public String buildLogoutRequest(Tenant tenant, User user, SamlServiceProvider sp) {
        return buildLogoutRequest(tenant, user, sp, Binding.POST);
    }

    private String buildLogoutRequestXml(Tenant tenant, User user, SamlServiceProvider sp) {
        String issuer = tenant.getSlug() + "-idp";
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
        List<SamlServiceProvider> sps = spRepository.findByTenantIdAndEnabledTrue(tenant.getId());
        List<SloPayload> payloads = new ArrayList<>();

        for (SamlServiceProvider sp : sps) {
            if (sp.getSloUrl() == null || sp.getSloUrl().isBlank()) {
                log.debug("SP {} has no SLO URL — skipping", sp.getEntityId());
                continue;
            }
            String encoded = buildLogoutRequest(tenant, user, sp, binding);
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
     * Build a LogoutResponse for an SP-initiated LogoutRequest. The
     * response echoes the request ID in {@code InResponseTo} and reports
     * {@code urn:oasis:names:tc:SAML:2.0:status:Success}.
     *
     * Returns the response encoded for the given binding, ready for the
     * controller to deliver via redirect or auto-submit form.
     */
    public String buildLogoutResponse(Tenant tenant, SamlServiceProvider sp,
                                       String inResponseTo, Binding binding) {
        String issuer = tenant.getSlug() + "-idp";
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
        xml.append("  <samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>\n");
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
