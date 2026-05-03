package tech.cwvermaak.weldforge.service.ldap;

import io.github.resilience4j.circuitbreaker.CallNotPermittedException;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import tech.cwvermaak.weldforge.model.TenantLdapProvider;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Production {@link LdapClient} backed by JNDI. Two-phase bind:
 *
 * <ol>
 *   <li>Service bind (or anonymous if {@code bindDn} is empty) →
 *       subtree search using {@code userSearchFilter} with {@code {0}}
 *       substituted for the submitted username.</li>
 *   <li>Rebind as the located DN with the submitted password — a success
 *       means the directory has verified the credentials.</li>
 * </ol>
 *
 * <p>All JNDI calls run inside the {@code upstream-idp} circuit breaker
 * (PRD AVL-04) so a flaky directory can't cascade into the auth thread
 * pool.
 */
@Component
@Slf4j
public class JndiLdapClient implements LdapClient {

    private static final String CB_NAME = "upstream-idp";

    private final CircuitBreaker circuitBreaker;

    public JndiLdapClient(CircuitBreakerRegistry registry) {
        this.circuitBreaker = registry.circuitBreaker(CB_NAME);
    }

    @Override
    public Optional<LdapAttributes> authenticate(TenantLdapProvider provider, String username, String password) {
        if (provider == null || username == null || username.isBlank() || password == null) {
            return Optional.empty();
        }
        try {
            return circuitBreaker.executeSupplier(() -> wrap(() -> doAuthenticate(provider, username, password)));
        } catch (CallNotPermittedException cbOpen) {
            log.warn("LDAP CB open — rejecting authenticate for tenant {} user {}",
                    provider.getTenant() != null ? provider.getTenant().getSlug() : "?", username);
            return Optional.empty();
        } catch (Exception e) {
            log.debug("LDAP authenticate failed: {}", e.getMessage());
            return Optional.empty();
        }
    }

    @Override
    public boolean testConnection(TenantLdapProvider provider) {
        if (provider == null) return false;
        try {
            return circuitBreaker.executeSupplier(() -> wrap(() -> {
                DirContext ctx = bindAsService(provider);
                try { ctx.close(); } catch (Exception ignored) {}
                return Boolean.TRUE;
            }));
        } catch (CallNotPermittedException cbOpen) {
            return false;
        } catch (Exception e) {
            log.debug("LDAP test connection failed: {}", e.getMessage());
            return false;
        }
    }

    /** Small helper: lets a lambda body throw checked exceptions under the CB. */
    private interface CheckedSupplier<T> { T get() throws Exception; }

    private static <T> T wrap(CheckedSupplier<T> supplier) {
        try {
            return supplier.get();
        } catch (RuntimeException rethrow) {
            throw rethrow;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // ---- Internals -------------------------------------------------

    private Optional<LdapAttributes> doAuthenticate(TenantLdapProvider provider, String username, String password) throws Exception {
        DirContext serviceCtx = bindAsService(provider);
        try {
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            controls.setReturningAttributes(new String[]{
                    provider.getEmailAttribute(),
                    provider.getNameAttribute(),
                    provider.getUsernameAttribute(),
                    "memberOf"
            });
            String filter = provider.getUserSearchFilter();
            NamingEnumeration<SearchResult> results = serviceCtx.search(
                    provider.getUserBaseDn(), filter, new Object[]{username}, controls);
            if (!results.hasMore()) return Optional.empty();
            SearchResult result = results.next();
            String dn = result.getNameInNamespace();

            // Phase 2: verify the password by binding as the user's DN.
            DirContext userCtx = bind(provider, dn, password);
            try { userCtx.close(); } catch (Exception ignored) {}

            Map<String, Object> attrs = flattenAttributes(result.getAttributes());
            return Optional.of(new LdapAttributes(dn, attrs));
        } catch (Exception e) {
            log.debug("LDAP search/bind failed for user {}: {}", username, e.getMessage());
            return Optional.empty();
        } finally {
            try { serviceCtx.close(); } catch (Exception ignored) {}
        }
    }

    private DirContext bindAsService(TenantLdapProvider provider) throws Exception {
        return bind(provider, provider.getBindDn(), provider.getBindPassword());
    }

    private DirContext bind(TenantLdapProvider provider, String dn, String password) throws Exception {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, provider.getUrl());
        if (dn != null && !dn.isBlank()) {
            env.put(Context.SECURITY_AUTHENTICATION, "simple");
            env.put(Context.SECURITY_PRINCIPAL, dn);
            env.put(Context.SECURITY_CREDENTIALS, password == null ? "" : password);
        } else {
            env.put(Context.SECURITY_AUTHENTICATION, "none");
        }
        if (provider.getUrl() != null && provider.getUrl().startsWith("ldaps://")) {
            env.put(Context.SECURITY_PROTOCOL, "ssl");
        }
        env.put("com.sun.jndi.ldap.connect.timeout", String.valueOf(provider.getConnectTimeoutMs()));
        env.put("com.sun.jndi.ldap.read.timeout", String.valueOf(provider.getReadTimeoutMs()));
        return new InitialDirContext(env);
    }

    private static Map<String, Object> flattenAttributes(Attributes attrs) throws Exception {
        Map<String, Object> out = new LinkedHashMap<>();
        if (attrs == null) return out;
        NamingEnumeration<? extends Attribute> e = attrs.getAll();
        while (e.hasMore()) {
            Attribute a = e.next();
            if (a.size() == 1) {
                out.put(a.getID(), a.get());
            } else {
                java.util.List<Object> vals = new java.util.ArrayList<>(a.size());
                for (int i = 0; i < a.size(); i++) vals.add(a.get(i));
                out.put(a.getID(), vals);
            }
        }
        return out;
    }
}
