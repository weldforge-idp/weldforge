package tech.cwvermaak.weldforge.service.mail;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.mail.MailSendException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * B-? observability: SmtpMailService emits sso.mail.send{outcome=success|failure}
 * so a silent SMTP failure (which still returns success to the caller) is visible.
 */
class SmtpMailServiceTest {

    private JavaMailSender mailSender;
    private SimpleMeterRegistry registry;
    private SmtpMailService service;

    @BeforeEach
    void setUp() {
        mailSender = mock(JavaMailSender.class);
        registry = new SimpleMeterRegistry();
        service = new SmtpMailService(mailSender, "no-reply@weldforge.test", registry);
    }

    private double count(String outcome) {
        var c = registry.find("sso.mail.send").tag("outcome", outcome).counter();
        return c == null ? 0.0 : c.count();
    }

    @Test
    @DisplayName("a successful send increments sso.mail.send{outcome=success}")
    void success_increments() {
        service.send("a@b.test", "Subject", "Body");

        assertThat_(count("success"), 1.0);
        assertThat_(count("failure"), 0.0);
    }

    @Test
    @DisplayName("a delivery failure increments {outcome=failure} and never propagates")
    void failure_incrementsAndSwallows() {
        doThrow(new MailSendException("smtp down")).when(mailSender).send(any(SimpleMailMessage.class));

        assertThatCode(() -> service.send("a@b.test", "Subject", "Body")).doesNotThrowAnyException();

        assertThat_(count("failure"), 1.0);
        assertThat_(count("success"), 0.0);
    }

    private static void assertThat_(double actual, double expected) {
        org.assertj.core.api.Assertions.assertThat(actual).isEqualTo(expected);
    }
}
