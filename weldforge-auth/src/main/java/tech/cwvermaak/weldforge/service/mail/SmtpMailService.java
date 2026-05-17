package tech.cwvermaak.weldforge.service.mail;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Primary;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
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
 *   SPRING_MAIL_PROPERTIES_MAIL_SMTP_STARTTLS_ENABLE=true,
 *   APP_MAIL_FROM=no-reply&#64;your-domain
 * </pre>
 */
@Service
@Primary
@ConditionalOnProperty(name = "spring.mail.host")
@Slf4j
public class SmtpMailService implements MailService {

    private final JavaMailSender mailSender;
    private final String from;

    public SmtpMailService(JavaMailSender mailSender,
                           @Value("${app.mail.from:no-reply@weldforge.org}") String from) {
        this.mailSender = mailSender;
        this.from = from;
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
            log.info("Sent email: to={} subject=\"{}\"", to, subject);
        } catch (Exception e) {
            // MailService contract: a delivery failure must never roll back or
            // block the security operation that triggered the send.
            log.error("Email delivery to {} failed: {}", to, e.toString());
        }
    }
}
