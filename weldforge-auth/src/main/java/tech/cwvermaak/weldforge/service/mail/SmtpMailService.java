package tech.cwvermaak.weldforge.service.mail;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Primary;
import jakarta.mail.internet.MimeMessage;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

/**
 * SMTP-backed {@link MailService} — real email delivery.
 *
 * <p>Registered <b>only</b> when an SMTP host is configured
 * ({@code spring.mail.host}); otherwise {@link LoggingMailService} remains
 * the sole {@code MailService}. When both beans are present this one is
 * {@link Primary}, so it wins every injection point. Deploying this code
 * with no SMTP config is therefore a no-op.
 *
 * <p>Configure at deploy time (env vars / Kubernetes secret — never committed):
 * <pre>
 *   SPRING_MAIL_HOST, SPRING_MAIL_PORT,
 *   SPRING_MAIL_USERNAME, SPRING_MAIL_PASSWORD,
 *   SPRING_MAIL_PROPERTIES_MAIL_SMTP_AUTH=true,
 *   APP_MAIL_FROM=no-reply&#64;your-domain
 * </pre>
 *
 * <p>The TLS setting depends on the port and the two are not interchangeable:
 * <ul>
 *   <li><b>465</b> — implicit SSL, TLS from the first byte:
 *       {@code ...MAIL_SMTP_SSL_ENABLE=true}, STARTTLS <b>false</b>.</li>
 *   <li><b>587</b> — starts in the clear and upgrades:
 *       {@code ...MAIL_SMTP_STARTTLS_ENABLE=true}, SSL <b>false</b>.</li>
 * </ul>
 * Asking for STARTTLS on 465 does not fall back — the handshake fails or the
 * connection hangs until timeout, and the error names nothing useful. The Helm
 * chart derives both flags from the port so this cannot be set inconsistently.
 */
@Service
@Primary
@ConditionalOnProperty(name = "spring.mail.host")
@Slf4j
public class SmtpMailService implements MailService {

    private static final String METRIC = "sso.mail.send";

    private final JavaMailSender mailSender;
    private final String from;
    private final io.micrometer.core.instrument.MeterRegistry meterRegistry;

    public SmtpMailService(JavaMailSender mailSender,
                           @Value("${app.mail.from:no-reply@weldforge.org}") String from,
                           io.micrometer.core.instrument.MeterRegistry meterRegistry) {
        this.mailSender = mailSender;
        this.from = from;
        this.meterRegistry = meterRegistry;
    }

    private void recordOutcome(String outcome) {
        // sso.mail.send{outcome=success|failure} — a delivery failure is logged
        // but the triggering security op (reset / verify) still returns success,
        // so this counter is the only signal that account recovery is silently
        // broken. Alert on a non-zero failure rate.
        meterRegistry.counter(METRIC, "outcome", outcome).increment();
    }

    @Override
    public void send(String to, String subject, String body) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(from);
            message.setTo(to);
            message.setSubject(subject);
            message.setText(body);
            mailSender.send(message);
            recordOutcome("success");
            log.info("Sent email: to={} subject=\"{}\"", to, subject);
        } catch (Exception e) {
            // MailService contract: a delivery failure must never roll back or
            // block the security operation that triggered the send.
            recordOutcome("failure");
            log.error("Email delivery to {} failed: {}", to, e.toString());
        }
    }

    @Override
    public void send(String to, String subject, String textBody, String htmlBody) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");
            helper.setFrom(from);
            helper.setTo(to);
            helper.setSubject(subject);
            // text + html → a multipart/alternative message: clients that
            // can't render HTML fall back to the plain-text part.
            helper.setText(textBody, htmlBody);
            mailSender.send(message);
            recordOutcome("success");
            log.info("Sent email (multipart): to={} subject=\"{}\"", to, subject);
        } catch (Exception e) {
            recordOutcome("failure");
            log.error("Email delivery to {} failed: {}", to, e.toString());
        }
    }
}
