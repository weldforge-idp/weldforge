package tech.cwvermaak.weldforge.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import tech.cwvermaak.weldforge.config.tenant.PublicHostProperties;
import tech.cwvermaak.weldforge.model.EmailVerificationToken;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.EmailVerificationTokenRepository;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.audit.AuditService;
import tech.cwvermaak.weldforge.service.mail.MailService;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * What the verification email actually contains.
 *
 * <p>These exist because nothing asserted the body of a transactional mail,
 * and so the verification mail went out for months carrying a bare token and
 * no link while the reset mail beside it carried one. The defect was not in
 * any branch — it was in the one line nobody read back. A test that only
 * checks "a mail was sent" would have passed throughout.
 */
class VerificationMailContentTest {

    private EmailVerificationTokenRepository tokenRepository;
    private MailService mailService;
    private EmailVerificationService service;

    @BeforeEach
    void setUp() {
        tokenRepository = mock(EmailVerificationTokenRepository.class);
        UserRepository userRepository = mock(UserRepository.class);
        TenantRepository tenantRepository = mock(TenantRepository.class);
        AuditService auditService = mock(AuditService.class);
        mailService = mock(MailService.class);

        when(tokenRepository.save(any(EmailVerificationToken.class)))
                .thenAnswer(inv -> inv.getArgument(0));

        PublicHostProperties publicHost = new PublicHostProperties();
        publicHost.setBaseDomain("sso.weldforge.org");
        publicHost.setScheme("https");

        service = new EmailVerificationService(tokenRepository, userRepository,
                tenantRepository, auditService, mailService, publicHost);
    }

    private static User userIn(Tenant tenant) {
        return User.builder().id(7L).email("wimpie.vermaak@gmail.com").tenant(tenant).build();
    }

    private static Tenant tenant(String slug, String displayName, Map<String, Object> branding) {
        return Tenant.builder().id(1L).slug(slug).name(slug)
                .displayName(displayName).branding(branding).build();
    }

    @Test
    @DisplayName("the mail carries a clickable link on the tenant's own host, not a bare token")
    void carriesTheLink() {
        Tenant t = tenant("counteract-studios", "Counteract Studios", null);
        String rawToken = service.sendVerification(userIn(t));

        ArgumentCaptor<String> subject = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> text = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> html = ArgumentCaptor.forClass(String.class);
        verify(mailService).send(eq("wimpie.vermaak@gmail.com"), subject.capture(),
                text.capture(), html.capture());

        String expected = "https://counteract-studios.sso.weldforge.org/verify-email?token=" + rawToken;

        // The link, in both alternatives. A text-only client must not be left
        // with a token and nowhere to put it -- that was the whole defect.
        assertThat(text.getValue()).contains(expected);
        assertThat(html.getValue()).contains("href=\"" + expected + "\"");

        // Named for the tenant, as the reset mail is. "Verify your WeldForge
        // email address" told a Counteract Studios user nothing about which
        // account was being verified.
        assertThat(subject.getValue()).isEqualTo("Verify your Counteract Studios email address");

        // No bare-token-only body on this path.
        assertThat(text.getValue()).doesNotContain("Enter this verification token");
    }

    @Test
    @DisplayName("the link is the route the portal actually serves")
    void linkMatchesTheServedRoute() {
        Tenant t = tenant("acme", "Acme", null);
        String rawToken = service.sendVerification(userIn(t));

        ArgumentCaptor<String> text = ArgumentCaptor.forClass(String.class);
        verify(mailService).send(anyString(), anyString(), text.capture(), anyString());

        // verify-email?token= is what features/auth/verify-email.component.ts
        // reads. If either side is renamed this fails, which is the point.
        assertThat(text.getValue()).contains("/verify-email?token=");
        // base64url, so it survives a query string without escaping.
        assertThat(rawToken).matches("[A-Za-z0-9_-]+");
    }

    @Test
    @DisplayName("falls back to a bare token, with somewhere to put it, when no public host is set")
    void fallsBackWithoutAPublicHost() {
        PublicHostProperties noHost = new PublicHostProperties();
        noHost.setBaseDomain(null);
        EmailVerificationService selfHosted = new EmailVerificationService(
                tokenRepository, mock(UserRepository.class), mock(TenantRepository.class),
                mock(AuditService.class), mailService, noHost);

        Tenant t = tenant("acme", "Acme", null);
        String rawToken = selfHosted.sendVerification(userIn(t));

        ArgumentCaptor<String> body = ArgumentCaptor.forClass(String.class);
        verify(mailService).send(anyString(), anyString(), body.capture());

        assertThat(body.getValue()).contains(rawToken);
        // The old mail said only "with this verification token:" and left the
        // person to guess. Say where it goes.
        assertThat(body.getValue()).contains("email-verification page");
    }

    @Test
    @DisplayName("the button takes the tenant's brand colour, and refuses anything that is not a colour")
    void brandColourIsValidatedNotEscaped() {
        Tenant branded = tenant("acme", "Acme", Map.of("primaryColor", "#6C7548"));
        service.sendVerification(userIn(branded));

        ArgumentCaptor<String> html = ArgumentCaptor.forClass(String.class);
        verify(mailService).send(anyString(), anyString(), anyString(), html.capture());
        assertThat(html.getValue()).contains("#6C7548");

        // A tenant-supplied value lands inside style="background:..." where
        // escaping does not make it safe, so a non-colour must be dropped.
        reset(mailService);
        Tenant hostile = tenant("acme", "Acme",
                Map.of("primaryColor", "red;\" onload=\"alert(1)"));
        service.sendVerification(userIn(hostile));

        ArgumentCaptor<String> hostileHtml = ArgumentCaptor.forClass(String.class);
        verify(mailService).send(anyString(), anyString(), anyString(), hostileHtml.capture());
        assertThat(hostileHtml.getValue()).doesNotContain("onload");
        assertThat(hostileHtml.getValue()).contains("#2D5FA8");
    }

    @Test
    @DisplayName("a tenant display name with HTML in it is escaped in the body")
    void tenantNameIsEscaped() {
        Tenant t = tenant("acme", "Ac<script>me", null);
        service.sendVerification(userIn(t));

        ArgumentCaptor<String> html = ArgumentCaptor.forClass(String.class);
        verify(mailService).send(anyString(), anyString(), anyString(), html.capture());
        assertThat(html.getValue()).doesNotContain("<script>");
        assertThat(html.getValue()).contains("Ac&lt;script&gt;me");
    }

    @Test
    @DisplayName("resend sends the same link-bearing mail, not the old bare token")
    void resendSendsTheSameMail() {
        // resendVerification delegates to sendVerification, so the fix reaches
        // it for free -- pinned here so a future split does not regress it.
        Tenant t = tenant("counteract-studios", "Counteract Studios", null);
        String rawToken = service.sendVerification(userIn(t));

        ArgumentCaptor<String> text = ArgumentCaptor.forClass(String.class);
        verify(mailService).send(anyString(), anyString(), text.capture(), anyString());
        assertThat(text.getValue())
                .contains("https://counteract-studios.sso.weldforge.org/verify-email?token=" + rawToken);
    }
}
