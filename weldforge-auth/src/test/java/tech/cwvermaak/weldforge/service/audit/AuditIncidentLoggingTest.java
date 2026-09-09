package tech.cwvermaak.weldforge.service.audit;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import tech.cwvermaak.weldforge.model.AuditEvent;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.repository.AuditEventRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.service.webhook.WebhookPublisher;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Incident logging: every audit event must reach the log stream, and must
 * survive the database failing.
 *
 * <p>{@code logback-spring.xml} has always declared a {@code security.audit}
 * logger and documented it as the split point for a SIEM. Nothing ever wrote to
 * it, so audit events lived only in the database — invisible to any log
 * pipeline, and <em>lost entirely</em> when the write failed, since the catch
 * block recorded the exception without the event.
 *
 * <p>The database-failure test is the one that matters. That is the moment the
 * record is most needed and was least likely to exist.
 */
class AuditIncidentLoggingTest {

    private AuditService auditService;
    private AuditEventRepository repository;
    private ListAppender<ILoggingEvent> appender;
    private Logger auditLogger;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        repository = mock(AuditEventRepository.class);
        TenantRepository tenantRepository = mock(TenantRepository.class);
        ObjectProvider<WebhookPublisher> publisher = mock(ObjectProvider.class);
        when(publisher.getIfAvailable()).thenReturn(null);

        auditService = new AuditService(repository, tenantRepository, publisher);

        auditLogger = (Logger) LoggerFactory.getLogger("security.audit");
        appender = new ListAppender<>();
        appender.start();
        auditLogger.addAppender(appender);
        auditLogger.setLevel(Level.INFO);
    }

    @AfterEach
    void tearDown() {
        auditLogger.detachAppender(appender);
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

    private List<ILoggingEvent> emitted() {
        return appender.list;
    }

    @Test
    @DisplayName("A successful audit event reaches the security.audit logger at INFO")
    void success_is_logged_at_info() {
        auditService.log(event("auth.login", AuditEvent.Outcome.SUCCESS));

        assertThat(emitted()).hasSize(1);
        assertThat(emitted().get(0).getLevel()).isEqualTo(Level.INFO);
    }

    @Test
    @DisplayName("A denied event is an incident and goes out at WARN")
    void denied_is_logged_at_warn() {
        // Level is what an operator alerts on, so severity has to be encoded
        // there rather than only inside the message.
        auditService.log(event("oidc.code.replay_detected", AuditEvent.Outcome.DENIED));

        assertThat(emitted()).hasSize(1);
        assertThat(emitted().get(0).getLevel()).isEqualTo(Level.WARN);
    }

    @Test
    @DisplayName("A failure event also goes out at WARN")
    void failure_is_logged_at_warn() {
        auditService.log(event("mfa.challenge.failed", AuditEvent.Outcome.FAILURE));

        assertThat(emitted().get(0).getLevel()).isEqualTo(Level.WARN);
    }

    @Test
    @DisplayName("The event survives the database write failing, with its content intact")
    void event_survives_a_database_failure() {
        // The case the old code lost outright: it logged that AN audit write had
        // failed, without saying which incident. Database trouble is something
        // an attacker can cause, so this is exactly when the record matters.
        when(repository.save(any(AuditEvent.class)))
                .thenThrow(new RuntimeException("connection refused"));

        auditService.log(event("auth.login.failed", AuditEvent.Outcome.FAILURE));

        assertThat(emitted()).hasSize(1);
        ILoggingEvent logged = emitted().get(0);
        assertThat(logged.getLevel()).isEqualTo(Level.WARN);

        String rendered = renderFields(logged);
        assertThat(rendered)
                .contains("auth.login.failed")
                .contains("alice@leap.test")
                .contains("leap")
                .contains("persisted=false");
    }

    @Test
    @DisplayName("A persisted event is marked as such, so an incomplete table is detectable")
    void persisted_flag_distinguishes_the_two() {
        auditService.log(event("auth.login", AuditEvent.Outcome.SUCCESS));

        assertThat(renderFields(emitted().get(0))).contains("persisted=true");
    }

    @Test
    @DisplayName("Structured fields carry the detail, so a SIEM need not parse prose")
    void fields_are_structured() {
        auditService.log(event("auth.login", AuditEvent.Outcome.SUCCESS));

        String rendered = renderFields(emitted().get(0));
        assertThat(rendered)
                .contains("event_type=auth.login")
                .contains("outcome=SUCCESS")
                .contains("target_type=user")
                .contains("target_id=42");
    }

    @Test
    @DisplayName("The rendered line carries the detail, not just the arguments")
    void rendered_line_is_readable() {
        // Regression guard. The first version logged a bare "audit" message,
        // and SLF4J only renders arguments a placeholder consumes -- so on the
        // console pattern the line read "audit" and nothing else. Both staging
        // and production run that pattern (neither sets SPRING_PROFILES_ACTIVE),
        // so every audit line was detail-free where it mattered.
        //
        // Asserting on getFormattedMessage rather than the argument array is
        // the point: the arguments were always present, and the line was still
        // useless.
        auditService.log(event("auth.login.failed", AuditEvent.Outcome.FAILURE));

        String rendered = emitted().get(0).getFormattedMessage();
        assertThat(rendered)
                .contains("event_type=auth.login.failed")
                .contains("outcome=FAILURE")
                .contains("actor_email=alice@leap.test")
                .contains("persisted=true");
    }

    @Test
    @DisplayName("A logging failure never escalates into a failure of the audited operation")
    void logging_failure_is_contained() {
        // An event with no tenant and no outcome: the emitter must cope rather
        // than throw, because it runs on the failure path of the thing that was
        // already going wrong.
        auditService.log(AuditEvent.builder().eventType("bare.event"));

        assertThat(emitted()).hasSize(1);
    }

    /** Renders the structured arguments the way an appender would see them. */
    private static String renderFields(ILoggingEvent logged) {
        StringBuilder out = new StringBuilder(logged.getFormattedMessage());
        for (Object argument : logged.getArgumentArray()) {
            out.append(' ').append(argument);
        }
        return out.toString();
    }
}
