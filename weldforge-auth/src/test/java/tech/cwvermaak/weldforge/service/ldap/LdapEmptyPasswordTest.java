package tech.cwvermaak.weldforge.service.ldap;

import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.TenantLdapProvider;
import tech.cwvermaak.weldforge.repository.TenantLdapProviderRepository;

import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * A simple bind with a DN and a zero-length password is an "unauthenticated
 * bind" (RFC 4513 5.1.2), and many directories -- Active Directory among them
 * -- answer it with SUCCESS without checking anything. WeldForge refused only a
 * null password, so {@code {"identifier":"ceo","password":""}} on a tenant
 * with LDAP enabled could sign in as any directory user (standards
 * assessment, 2026-11-15).
 *
 * <p>No embedded directory is needed to prove the fix: the provider points at
 * a local socket that counts connections. An empty password must never reach
 * the directory at all; a real one must, which shows the probe can see a
 * connection when there is one.
 */
@DisplayName("LDAP: an empty password never reaches the directory")
class LdapEmptyPasswordTest {

    private ServerSocket directory;
    private final AtomicInteger connections = new AtomicInteger();
    private Thread acceptor;
    private JndiLdapClient client;

    @BeforeEach
    void startFakeDirectory() throws Exception {
        directory = new ServerSocket(0);
        directory.setSoTimeout(200);
        acceptor = new Thread(() -> {
            while (!directory.isClosed()) {
                try (Socket s = directory.accept()) {
                    connections.incrementAndGet();
                } catch (SocketTimeoutException ignored) {
                    // keep polling until closed
                } catch (Exception closed) {
                    return;
                }
            }
        });
        acceptor.setDaemon(true);
        acceptor.start();
        client = new JndiLdapClient(CircuitBreakerRegistry.ofDefaults());
    }

    @AfterEach
    void stopFakeDirectory() throws Exception {
        directory.close();
        acceptor.join(2000);
    }

    private TenantLdapProvider provider(String bindPassword) {
        return TenantLdapProvider.builder()
                .tenant(Tenant.builder().id(1L).slug("acme").build())
                .url("ldap://127.0.0.1:" + directory.getLocalPort())
                .bindDn("cn=svc,dc=acme,dc=test")
                .bindPassword(bindPassword)
                .userBaseDn("dc=acme,dc=test")
                .connectTimeoutMs(500)
                .readTimeoutMs(500)
                .build();
    }

    /** Lets the acceptor thread record any connection the call made. */
    private int connectionsAfter(Runnable call) throws InterruptedException {
        call.run();
        Thread.sleep(400);
        return connections.get();
    }

    @Test
    @DisplayName("an empty user password is refused without contacting the directory")
    void emptyPasswordNeverConnects() throws Exception {
        TenantLdapProvider p = provider("service-secret");

        int seen = connectionsAfter(() ->
                assertThat(client.authenticate(p, "ceo", "")).isEmpty());

        assertThat(seen).isZero();
    }

    @Test
    @DisplayName("a real password does reach the directory, so the probe can see a connection")
    void realPasswordConnects() throws Exception {
        TenantLdapProvider p = provider("service-secret");

        int seen = connectionsAfter(() -> client.authenticate(p, "ceo", "a-real-password"));

        assertThat(seen).isPositive();
    }

    @Test
    @DisplayName("a service account configured with a DN and an empty password is not bound unauthenticated")
    void emptyServiceBindPasswordNeverConnects() throws Exception {
        TenantLdapProvider p = provider("");

        int seen = connectionsAfter(() -> assertThat(client.testConnection(p)).isFalse());

        assertThat(seen).isZero();
    }

    @Test
    @DisplayName("the upstream service refuses an empty password before asking any provider")
    void serviceRefusesBeforeAnyProvider() {
        TenantLdapProviderRepository providers = mock(TenantLdapProviderRepository.class);
        LdapClient ldap = mock(LdapClient.class);
        when(providers.findByTenantIdAndEnabledTrue(any())).thenReturn(List.of(provider("service-secret")));
        LdapUpstreamService service = new LdapUpstreamService(providers, ldap, null, null, null);

        assertThat(service.authenticate(Tenant.builder().id(1L).slug("acme").build(), "ceo", "")).isEmpty();

        verify(ldap, never()).authenticate(any(), anyString(), anyString());
    }
}
