package tech.cwvermaak.weldforge.service.mail;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Default {@link MailService}: no SMTP transport is wired yet, so messages
 * are logged rather than sent.
 *
 * <p>The security point of this class is the log level split. The fact that
 * an email was queued is logged at {@code INFO}; the body — which carries
 * the single-use reset/verification token — is logged only at {@code DEBUG}.
 * Production runs at {@code INFO}, so tokens stay out of production logs.
 * A non-production environment that needs to read the token back enables
 * {@code DEBUG} on this one class.
 *
 * <p>To wire real delivery, add a transport-backed {@code MailService}
 * implementation and mark it {@code @Primary} (or remove this class).
 */
@Service
@Slf4j
public class LoggingMailService implements MailService {

    @Override
    public void send(String to, String subject, String body) {
        log.info("Outbound email queued: to={} subject=\"{}\"", to, subject);
        log.debug("Email body for {}:\n{}", to, body);
    }
}
