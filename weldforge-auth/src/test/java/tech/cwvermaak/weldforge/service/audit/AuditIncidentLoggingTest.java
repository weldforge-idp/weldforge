package tech.cwvermaak.weldforge.service.audit;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import tech.cwvermaak.weldforge.model.AuditEvent;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.repository.AuditEventRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.service.webhook.WebhookPublisher;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Incident logging: every audit event must reach the log stream, and must
 * survive the database failing.
 *
 * <p>The {@code security.audit} logger was declared in the logging
 * configuration and documented as the split point for a SIEM, but nothing ever
 * wrote to it. Audit events lived only in the database — invisible to any log
 * pipeline, and <em>lost entirely</em> when the write failed, since the catch
 * block recorded the exception without the event.
 *
 * <p>The database-failure test is the one that matters. That is the moment the
 * record is most needed and was least likely to exist.
 *
 * <p>Assertions read the MDC captured on each event rather than the rendered
 * string, because that is what the JSON template flattens into SIEM fields.
 * Testing the rendered console line would test the dev format instead of the
 * thing production ships.
 */
class AuditIncidentLoggingTest {

    private static final String AUDIT_LOGGER = "security.audit";

    private AuditService auditService;
    private AuditEventRepository repository;
    private CapturingAppender appender;
    private org.apache.logging.log4j.core.Logger auditLogger;
    private Level previousLevel;

    /** Minimal Log4j 2 appender that keeps the events it is given. */
    private static final class CapturingAppender extends AbstractAppender {
        private final List<LogEvent> events = new CopyOnWriteArrayList<>();

        CapturingAppender() {
            super("capturing", null, null, true, null);
        }

        @Override
        public void append(LogEvent event) {
            // Immutable snapshot: Log4j reuses the mutable event instance, so
            // holding the original would leave every captured entry showing the
            // last event's MDC.
            events.add(event.toImmutable());
        }
    }

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        repository = mock(AuditEventRepository.class);
        TenantRepository tenantRepository = mock(TenantRepository.class);
        ObjectProvider<WebhookPublisher> publisher = mock(ObjectProvider.class);
        when(publisher.getIfAvailable()).thenReturn(null);

        auditService = new AuditService(repository, tenantRepository, publisher);

        // Attach to the LOGGER, not to the Configuration object.
        //
        // Adding a LoggerConfig to the configuration returned by
        // getConfiguration() is lost the moment anything reconfigures the
        // context -- and a Spring Boot test starting up does exactly that,
        // reloading log4j2-spring.xml. That produced a test which passed alone
        // and captured nothing inside the full suite.
        //
        // core.Logger.addAppender resolves against whichever LoggerConfig is
        // bound at call time, and setUp runs immediately before each method, so
        // no reconfiguration can slip in between.
        auditLogger = (org.apache.logging.log4j.core.Logger) LogManager.getLogger(AUDIT_LOGGER);
        appender = new CapturingAppender();
        appender.start();
        previousLevel = auditLogger.getLevel();
        auditLogger.setLevel(Level.INFO);
        auditLogger.addAppender(appender);
    }

    @AfterEach
    void tearDown() {
        auditLogger.removeAppender(appender);
        auditLogger.setLevel(previousLevel);
        appender.stop();
    }

    private AuditEvent.AuditEventBuilder event(String type, AuditEvent.Outcome outcome) {
        return AuditEvent.builder()
                .eventType(type)
                .outcome(outcome)
                .actorEmail("alice@leap.test")
                .tenant(Tenant.builder().id(1L).slug("leap").name("Leap").build())
                .targetType("user")
                .targetId("42")
                .metadata(Map.of("reason", "test"));
    }

    private List<LogEvent> emitted() {
        return appender.events.stream()
                .filter(e -> AUDIT_LOGGER.equals(e.getLoggerName()))
                .toList();
    }

    /**
     * The audit line for one specific event type.
     *
     * <p>Deliberately not an assertion on the total count, and the event names
     * are unique to this class. Every test in this JVM shares the
     * {@code security.audit} logger name and the BDD suite drives AuditService
     * hard -- it emits {@code oidc.code.replay_detected} among others -- so
     * both a size assertion and a real event name match other suites' lines as
     * well as ours.
     */
    private LogEvent auditLineFor(String eventType) {
        List<LogEvent> matching = emitted().stream()
                .filter(e -> eventType.equals(fieldsOf(e).get("audit.event_type")))
                .toList();
        assertThat(matching)
                .as("expected exactly one security.audit line for %s", eventType)
                .hasSize(1);
        return matching.get(0);
    }

    private Map<String, String> fieldsOf(LogEvent logged) {
        return logged.getContextData() == null
                ? Collections.emptyMap()
                : logged.getContextData().toMap();
    }

    @Test
    @DisplayName("A successful audit event reaches the security.audit logger at INFO")
    void success_is_logged_at_info() {
        auditService.log(event("test.audit.success", AuditEvent.Outcome.SUCCESS));

        assertThat(auditLineFor("test.audit.success").getLevel()).isEqualTo(Level.INFO);
    }

    @Test
    @DisplayName("A denied event is an incident and goes out at WARN")
    void denied_is_logged_at_warn() {
        // Level is what an operator alerts on, so severity has to be encoded
        // there rather than only inside the message.
        auditService.log(event("test.audit.denied", AuditEvent.Outcome.DENIED));

        assertThat(auditLineFor("test.audit.denied").getLevel()).isEqualTo(Level.WARN);
    }

    @Test
    @DisplayName("A failure event also goes out at WARN")
    void failure_is_logged_at_warn() {
        auditService.log(event("test.audit.failure", AuditEvent.Outcome.FAILURE));

        assertThat(auditLineFor("test.audit.failure").getLevel()).isEqualTo(Level.WARN);
    }

    @Test
    @DisplayName("The event survives the database write failing, with its content intact")
    void event_survives_a_database_failure() {
        // The case the old code lost outright: it logged that AN audit write had
        // failed, without saying which incident. Database trouble is something
        // an attacker can cause, so this is exactly when the record matters.
        when(repository.save(any(AuditEvent.class)))
                .thenThrow(new RuntimeException("connection refused"));

        auditService.log(event("test.audit.db_failure", AuditEvent.Outcome.FAILURE));

        LogEvent logged = auditLineFor("test.audit.db_failure");
        assertThat(logged.getLevel()).isEqualTo(Level.WARN);

        assertThat(fieldsOf(logged))
                .containsEntry("audit.event_type", "test.audit.db_failure")
                .containsEntry("audit.actor_email", "alice@leap.test")
                .containsEntry("audit.tenant", "leap")
                .containsEntry("audit.persisted", "false");
    }

    @Test
    @DisplayName("A persisted event is marked as such, so an incomplete table is detectable")
    void persisted_flag_distinguishes_the_two() {
        auditService.log(event("test.audit.success", AuditEvent.Outcome.SUCCESS));

        assertThat(fieldsOf(auditLineFor("test.audit.success"))).containsEntry("audit.persisted", "true");
    }

    @Test
    @DisplayName("Fields arrive in the MDC, which is what the JSON template flattens")
    void fields_are_structured() {
        auditService.log(event("test.audit.success", AuditEvent.Outcome.SUCCESS));

        assertThat(fieldsOf(auditLineFor("test.audit.success")))
                .containsEntry("audit.event_type", "test.audit.success")
                .containsEntry("audit.outcome", "SUCCESS")
                .containsEntry("audit.target_type", "user")
                .containsEntry("audit.target_id", "42");
    }

    @Test
    @DisplayName("Audit fields do not leak onto the next log line")
    void mdc_is_scoped_to_the_audit_line() {
        auditService.log(event("test.audit.success", AuditEvent.Outcome.SUCCESS));

        // MdcEnrichmentFilter owns request_id/tenant/actor for the whole
        // request; audit.* keys left behind would stamp themselves onto every
        // unrelated line that followed.
        assertThat(org.slf4j.MDC.getCopyOfContextMap())
                .satisfiesAnyOf(
                        map -> assertThat(map).isNull(),
                        map -> assertThat(map).doesNotContainKey("audit.event_type"));
    }

    @Test
    @DisplayName("A logging failure never escalates into a failure of the audited operation")
    void logging_failure_is_contained() {
        // An event with no tenant and no outcome: the emitter must cope rather
        // than throw, because it runs on the failure path of the thing that was
        // already going wrong.
        auditService.log(AuditEvent.builder().eventType("test.audit.bare"));

        assertThat(auditLineFor("test.audit.bare")).isNotNull();
    }
}
