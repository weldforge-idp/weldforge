package tech.cwvermaak.weldforge.service.audit;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
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

    /**
     * Dedicated SLF4J logger for security incidents.
     *
     * <p>{@code logback-spring.xml} has always declared this logger and
     * documented its purpose -- "auth-related events are tagged with logger
     * name security.audit so downstream pipelines can split them from noisy
     * HTTP access logs" -- but nothing ever wrote to it, so the split it
     * promises did not exist and audit events lived only in the database.
     *
     * <p>Two things follow from that. A SIEM could not see them at all. And
     * when the database write failed, the event content was lost outright:
     * the catch below logged that <em>an</em> audit write had failed, without
     * saying which incident it was. The moment you most need the record --
     * database trouble, which an attacker can cause -- is the moment it
     * disappeared.
     *
     * <p>Every event now reaches the log stream as well as the table, so the
     * two fail independently.
     */
    private static final org.slf4j.Logger AUDIT =
            org.slf4j.LoggerFactory.getLogger("security.audit");

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
            emit(event, true);
        } catch (Exception e) {
            // The event still has to be recorded somewhere. Emitting it here --
            // with its full content, not just the exception -- is what stops an
            // incident vanishing because the database was the thing failing.
            if (event != null) {
                emit(event, false);
            }
            log.error("Failed to persist audit event {}: {}",
                    event == null ? "(unbuilt)" : event.getEventType(), e.getMessage(), e);
        }
        if (event != null) publishWebhook(event);
    }

    /**
     * Emit an audit event to the {@code security.audit} logger.
     *
     * <p>Fields go out through the MDC, so the {@code prod} JSON template
     * flattens them into real fields a SIEM can filter on, while the dev
     * console still shows a readable summary. Using the MDC rather than a
     * logging-implementation-specific structured argument keeps this class on
     * the SLF4J facade: it survived the Logback to Log4j 2 migration without
     * a change to what it asserts.
     *
     * <p>Level encodes severity so an operator can alert on one line:
     * {@code DENIED} and {@code FAILURE} are the incidents worth waking up for
     * and go out at WARN; a successful action is INFO. {@code persisted=false}
     * is always WARN regardless of outcome -- an event that reached only the
     * log is itself a problem, because the audit table is now incomplete.
     *
     * <p>Never throws. Logging an audit event must not be able to break the
     * operation being audited, and this method is on the failure path of the
     * one thing that was already going wrong.
     */
    private void emit(AuditEvent event, boolean persisted) {
        Map<String, String> fields = new HashMap<>();
        try {
            put(fields, "audit.event_type", event.getEventType());
            put(fields, "audit.outcome", event.getOutcome() == null ? null : event.getOutcome().name());
            put(fields, "audit.actor_email", event.getActorEmail());
            put(fields, "audit.tenant", event.getTenant() == null ? null : event.getTenant().getSlug());
            put(fields, "audit.target_type", event.getTargetType());
            put(fields, "audit.target_id", event.getTargetId());
            put(fields, "audit.ip_address", event.getIpAddress());
            put(fields, "audit.metadata", event.getMetadata() == null ? null : event.getMetadata().toString());
            put(fields, "audit.persisted", Boolean.toString(persisted));

            fields.forEach(MDC::put);

            boolean incident = !persisted
                    || event.getOutcome() == AuditEvent.Outcome.DENIED
                    || event.getOutcome() == AuditEvent.Outcome.FAILURE;
            String summary = event.getEventType() + " outcome="
                    + (event.getOutcome() == null ? "UNKNOWN" : event.getOutcome().name())
                    + " persisted=" + persisted;
            if (incident) {
                AUDIT.warn(summary);
            } else {
                AUDIT.info(summary);
            }
        } catch (Exception e) {
            // Swallowed on purpose: see the javadoc. A failure to log must not
            // escalate into a failure of the audited operation.
            log.warn("Failed to emit audit event to the security.audit logger: {}", e.getMessage());
        } finally {
            // Scoped to this one line. MdcEnrichmentFilter owns request_id,
            // tenant and actor for the whole request; leaving audit.* behind
            // would stamp them onto every unrelated log line that followed.
            fields.keySet().forEach(MDC::remove);
        }
    }

    private static void put(Map<String, String> fields, String key, String value) {
        if (value != null) fields.put(key, value);
    }

    /**
     * Fan the audit event out to any matching webhook subscriptions
     * (PRD API-05). Publish failures are swallowed - webhook delivery is
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
        // B-AUTH-1: trust only the RemoteIpValve-resolved address
        // (server.forward-headers-strategy=native), never the spoofable raw
        // X-Forwarded-For leftmost token — otherwise audit rows record an
        // attacker-chosen client IP.
        return request.getRemoteAddr();
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
