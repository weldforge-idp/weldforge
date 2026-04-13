package tech.cwvermaak.intellisso.service.saml;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import tech.cwvermaak.intellisso.model.SamlServiceProvider;
import tech.cwvermaak.intellisso.model.Tenant;
import tech.cwvermaak.intellisso.model.TenantSigningKey;
import tech.cwvermaak.intellisso.model.User;
import tech.cwvermaak.intellisso.repository.SamlServiceProviderRepository;
import tech.cwvermaak.intellisso.service.audit.AuditEventTypes;
import tech.cwvermaak.intellisso.service.audit.AuditService;
import tech.cwvermaak.intellisso.service.oidc.TenantSigningKeyService;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

/**
 * SAML 2.0 IdP-initiated Single Logout. Builds LogoutRequest XML
 * messages for each SP registered with a SLO URL, so the controller
 * can deliver them (via HTTP-POST or HTTP-Redirect binding).
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SamlSloService {

    private final SamlServiceProviderRepository spRepository;
    private final TenantSigningKeyService signingKeyService;
    private final AuditService auditService;

    /**
     * Build a SAML LogoutRequest XML for a specific SP.
     *
     * @return base64-encoded LogoutRequest XML
     */
    public String buildLogoutRequest(Tenant tenant, User user, SamlServiceProvider sp) {
        String issuer = tenant.getSlug() + "-idp";
        String requestId = "_" + UUID.randomUUID();
        Instant now = Instant.now();

        String nameId = resolveNameId(user, sp.getNameIdFormat());

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

        return Base64.getEncoder().encodeToString(xml.toString().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Initiate IdP-initiated logout for a user across all SPs that have
     * a SLO URL configured. Returns a list of SP payloads the controller
     * can use to deliver the LogoutRequests.
     */
    public List<SloPayload> initiateLogout(Tenant tenant, User user) {
        List<SamlServiceProvider> sps = spRepository.findByTenantIdAndEnabledTrue(tenant.getId());

        List<SloPayload> payloads = new ArrayList<>();

        for (SamlServiceProvider sp : sps) {
            if (sp.getSloUrl() == null || sp.getSloUrl().isBlank()) {
                log.debug("SP {} has no SLO URL — skipping", sp.getEntityId());
                continue;
            }

            String logoutRequest = buildLogoutRequest(tenant, user, sp);
            payloads.add(new SloPayload(
                    sp.getId(),
                    sp.getEntityId(),
                    sp.getName(),
                    sp.getSloUrl(),
                    logoutRequest
            ));

            log.info("Built LogoutRequest for SP {} (entity_id={})", sp.getName(), sp.getEntityId());
        }

        auditService.recordUserAction(AuditEventTypes.SAML_IDP_LOGOUT_INITIATED, user,
                AuditEventTypes.TARGET_USER, String.valueOf(user.getId()),
                AuditService.meta(
                        "tenant_slug", tenant.getSlug(),
                        "sp_count", payloads.size()));

        return payloads;
    }

    /**
     * Payload for a single SP's logout request, returned to the controller
     * for delivery.
     */
    public record SloPayload(
            Long spId,
            String entityId,
            String spName,
            String sloUrl,
            String logoutRequest
    ) {}

    private static String resolveNameId(User user, String nameIdFormat) {
        if (nameIdFormat != null && nameIdFormat.contains("persistent")) {
            return String.valueOf(user.getId());
        }
        return user.getEmail();
    }

    private static String escapeXml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&apos;");
    }
}
