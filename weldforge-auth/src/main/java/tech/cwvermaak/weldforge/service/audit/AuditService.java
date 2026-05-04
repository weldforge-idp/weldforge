package tech.cwvermaak.weldforge.service.audit;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import tech.cwvermaak.weldforge.model.AuditEvent;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.AuditEventRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * Append-only audit sink. Services call {@link #log} to record a security
 * event; IP and user-agent are pulled from the current request automatically
 * so callers don't have to thread them through every signature.
 *
 * Each write runs in {@link Propagation#REQUIRES_NEW} so a failure to audit
 * never rolls back the caller's business transaction — a lost audit entry
 * is a log line, not a user-facing outage.
 */
@Service
@Slf4j
public class AuditService {

    private final AuditEventRepository repository;
    private final TenantRepository tenantRepository;
    // ObjectProvider avoids a circular dependency: WebhookPublisher
    // transitively depends on entities audited here.
    private final ObjectProvider<tech.cwvermaak.weldforge.service.webhook.WebhookPublisher> webhookPublisher;

    public AuditService(AuditEventRepository repository,
                        TenantRepository tenantRepository,
                        ObjectProvider<tech.cwvermaak.weldforge.service.webhook.WebhookPublisher> webhookPublisher) {
        this.repository = repository;
        this.tenantRepository = tenantRepository;
        this.webhookPublisher = webhookPublisher;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void log(AuditEvent.AuditEventBuilder builder) {
        AuditEvent event = null;
        try {
            event = buildWithContext(builder);
            repository.save(event);
        } catch (Exception e) {
            log.error("Failed to write audit event: {}", e.getMessage(), e);
        }
        if (event != null) publishWebhook(event);
    }

    /**
     * Fan the audit event out to any matching webhook subscriptions
     * (PRD API-05). Publish failures are swallowed — webhook delivery is
     * a side-effect of the primary operation and must never break it.
     */
    private void publishWebhook(AuditEvent event) {
        if (event.getTenant() == null || event.getEventType() == null) return;
        try {
            tech.cwvermaak.weldforge.service.webhook.WebhookPublisher publisher = webhookPublisher.getIfAvailable();
            if (publisher == null) return;
            Map<String, Object> data = new HashMap<>();
            data.put("outcome", event.getOutcome() != null ? event.getOutcome().name() : null);
            data.put("actor_email", event.getActorEmail());
            data.put("target_type", event.getTargetType());
            data.put("target_id", event.getTargetId());
            if (event.getMetadata() != null) data.put("metadata", event.getMetadata());
            publisher.publish(event.getEventType(), event.getTenant(), data);
        } catch (Exception e) {
            log.warn("Webhook fan-out for audit event {} failed: {}", event.getEventType(), e.getMessage());
        }
    }

    // ---- Convenience builders ---------------------------------------

    /** Successful event bound to a user (actor = the user themselves). */
    public void recordUserAction(String eventType, User actor, String targetType, String targetId,
                                 Map<String, Object> metadata) {
        log(AuditEvent.builder()
                .eventType(eventType)
                .outcome(AuditEvent.Outcome.SUCCESS)
                .tenant(actor != null ? actor.getTenant() : null)
                .actorUser(actor)
                .actorEmail(actor != null ? actor.getEmail() : null)
                .actorIsSuperAdmin(actor != null && actor.isSuperAdmin())
                .targetType(targetType)
                .targetId(targetId)
                .metadata(metadata));
    }

    /** Event bound to a tenant but where the actor isn't a user (e.g. anonymous failed login). */
    public void recordAnonymous(String eventType, AuditEvent.Outcome outcome, Long tenantId,
                                String actorEmail, String targetType, String targetId,
                                Map<String, Object> metadata) {
        Tenant tenant = tenantId != null
                ? tenantRepository.findById(tenantId).orElse(null)
                : null;
        log(AuditEvent.builder()
                .eventType(eventType)
                .outcome(outcome)
                .tenant(tenant)
                .actorEmail(actorEmail)
                .targetType(targetType)
                .targetId(targetId)
                .metadata(metadata));
    }

    /** Administrative action where actor and target may be in the same tenant. */
    public void recordAdmin(String eventType, User actor, String targetType, String targetId,
                            Map<String, Object> metadata) {
        recordUserAction(eventType, actor, targetType, targetId, metadata);
    }

    // ---- Search -----------------------------------------------------

    public Page<AuditEvent> search(Long tenantId, String eventType, String actorEmail,
                                   LocalDateTime since, LocalDateTime until,
                                   int page, int size) {
        return repository.search(tenantId, nullIfBlank(eventType), nullIfBlank(actorEmail),
                since, until, PageRequest.of(page, size));
    }

    // ---- Internals --------------------------------------------------

    private AuditEvent buildWithContext(AuditEvent.AuditEventBuilder builder) {
        HttpServletRequest request = currentRequest();
        if (request != null) {
            builder.ipAddress(clientIp(request))
                   .userAgent(truncate(request.getHeader("User-Agent"), 512));
        }
        return builder.build();
    }

    private static HttpServletRequest currentRequest() {
        Object attrs = RequestContextHolder.getRequestAttributes();
        if (attrs instanceof ServletRequestAttributes sra) return sra.getRequest();
        return null;
    }

    private static String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            int comma = forwarded.indexOf(',');
            return (comma == -1 ? forwarded : forwarded.substring(0, comma)).trim();
        }
        String real = request.getHeader("X-Real-IP");
        return real != null && !real.isBlank() ? real : request.getRemoteAddr();
    }

    private static String truncate(String s, int max) {
        if (s == null) return null;
        return s.length() <= max ? s : s.substring(0, max);
    }

    private static String nullIfBlank(String s) {
        return s == null || s.isBlank() ? null : s;
    }

    public static Map<String, Object> meta(Object... kv) {
        Map<String, Object> m = new HashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) {
            if (kv[i] != null && kv[i + 1] != null) {
                m.put(kv[i].toString(), kv[i + 1]);
            }
        }
        return m.isEmpty() ? null : m;
    }
}
