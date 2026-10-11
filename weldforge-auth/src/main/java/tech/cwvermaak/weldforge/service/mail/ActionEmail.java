package tech.cwvermaak.weldforge.service.mail;

import java.util.Map;

/**
 * Body builder for the transactional mails that ask a person to click one
 * link — password reset and email verification.
 *
 * <p>Shared on purpose. The verification mail shipped for months carrying a
 * bare token and no link while the reset mail beside it had always carried
 * one, because each built its own body and nothing held the two to the same
 * shape. A person who received the verification mail could not act on it:
 * there was nothing to click and nothing saying where a token goes.
 *
 * <p>So the shell lives here and both callers pass only their wording. The
 * button colour comes from the tenant's {@code branding.primaryColor}, which
 * is the same key the login screen uses — see {@code docs/tenant-branding.md}.
 */
public final class ActionEmail {

    /** Fallback button colour when the tenant has no usable primaryColor. */
    static final String DEFAULT_BUTTON_COLOR = "#2D5FA8";

    private ActionEmail() {
    }

    /**
     * Plain-text alternative. Carries the URL on a line of its own so that
     * mail clients which linkify text can find it, and so a person who has to
     * copy it by hand gets the whole thing.
     */
    public static String text(String intro, String prompt, String url, String footer) {
        return intro + "\n\n"
                + prompt + "\n" + url + "\n\n"
                + footer;
    }

    /**
     * HTML body: one heading, one paragraph, one button, and the same URL
     * repeated as text underneath. The repeat is not redundant — a client that
     * strips the button leaves the person with nothing otherwise.
     */
    public static String html(String heading, String intro, String buttonLabel,
                              String url, String buttonColor, String footer) {
        String html = """
            <!doctype html>
            <html><body style="margin:0;padding:0;background:#f3f4f6;">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f3f4f6;">
            <tr><td align="center" style="padding:32px 16px;">
            <table role="presentation" cellpadding="0" cellspacing="0" style="width:468px;max-width:468px;background:#ffffff;border:1px solid #e5e7eb;border-radius:8px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
            <tr><td style="padding:32px;">
            <h1 style="margin:0 0 16px;font-size:20px;color:#111827;">__HEADING__</h1>
            <p style="margin:0 0 24px;font-size:14px;line-height:1.6;color:#374151;">__INTRO__</p>
            <table role="presentation" cellpadding="0" cellspacing="0"><tr><td style="border-radius:6px;background:__COLOR__;">
            <a href="__URL__" style="display:inline-block;padding:12px 32px;font-size:14px;font-weight:600;color:#ffffff;text-decoration:none;">__BUTTON__</a>
            </td></tr></table>
            <p style="margin:24px 0 4px;font-size:12px;color:#6b7280;">Or paste this link into your browser:</p>
            <p style="margin:0;font-size:12px;word-break:break-all;"><a href="__URL__" style="color:__COLOR__;">__URL__</a></p>
            <p style="margin:24px 0 0;font-size:12px;color:#9ca3af;">__FOOTER__</p>
            </td></tr></table>
            </td></tr></table>
            </body></html>
            """;
        return html
                .replace("__HEADING__", escapeHtml(heading))
                .replace("__INTRO__", escapeHtml(intro))
                .replace("__BUTTON__", escapeHtml(buttonLabel))
                .replace("__COLOR__", buttonColor)
                .replace("__URL__", escapeHtml(url))
                .replace("__FOOTER__", escapeHtml(footer));
    }

    /**
     * The tenant's primary brand colour, when it is a plain hex literal we can
     * drop into a style attribute. Anything else falls back, because this value
     * is tenant-supplied and lands inside {@code style="background:…"} — a
     * colour is validated rather than escaped so that a value which cannot be
     * made safe is not used at all.
     */
    public static String buttonColor(Map<String, Object> branding) {
        Object pc = branding == null ? null : branding.get("primaryColor");
        if (pc instanceof String s && s.matches("#[0-9A-Fa-f]{3,8}")) {
            return s;
        }
        return DEFAULT_BUTTON_COLOR;
    }

    public static String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;")
                .replace(">", "&gt;").replace("\"", "&quot;");
    }
}
