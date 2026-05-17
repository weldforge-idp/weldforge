package tech.cwvermaak.weldforge.service.mail;

/**
 * Outbound transactional email — password resets, email verification, and
 * (future) admin invitations.
 *
 * <p>This is deliberately a thin seam. The default {@link LoggingMailService}
 * implementation has no SMTP transport; it exists so that security-sensitive
 * tokens are routed through a single, swappable component instead of being
 * written to the application log. A real SMTP/SES-backed implementation can
 * be dropped in by registering a bean that replaces the default.
 *
 * <p>Contract: implementations must treat a delivery failure as non-fatal —
 * a mail outage must never roll back or block the security operation that
 * triggered the send (a password reset still happens even if the email
 * cannot leave the building).
 */
public interface MailService {

    /**
     * Deliver a plain-text email.
     *
     * @param to      recipient address
     * @param subject message subject
     * @param body    plain-text body; may contain a single-use token, so
     *                implementations must keep it out of low-sensitivity logs
     */
    void send(String to, String subject, String body);

    /**
     * Deliver a multipart email — an HTML body with a plain-text alternative
     * for clients that don't render HTML.
     *
     * <p>The default implementation falls back to {@link #send(String, String, String)}
     * (plain text only); a transport-backed implementation overrides it to
     * send a true {@code multipart/alternative} message.
     *
     * @param to       recipient address
     * @param subject  message subject
     * @param textBody plain-text alternative (may carry a single-use token)
     * @param htmlBody HTML body
     */
    default void send(String to, String subject, String textBody, String htmlBody) {
        send(to, subject, textBody);
    }
}
