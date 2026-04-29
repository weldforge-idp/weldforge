package tech.cwvermaak.intellisso.service.ldap;

import tech.cwvermaak.intellisso.model.TenantLdapProvider;

import java.util.Map;
import java.util.Optional;

/**
 * Thin seam over the JNDI / LDAP transport so tests can inject a fake
 * without a real directory server. The production implementation uses
 * {@link javax.naming.directory.InitialDirContext} and wraps its calls
 * in the {@code upstream-idp} circuit breaker (PRD AVL-04).
 */
public interface LdapClient {

    /** Opaque attribute bag returned on a successful authentication. */
    record LdapAttributes(String dn, Map<String, Object> attributes) {}

    /**
     * Authenticate {@code username}/{@code password} against the given
     * provider. Returns the user's attributes on success, empty on any
     * kind of failure (bad credentials, user not found, directory
     * unreachable). Detailed failure reasons are logged, not returned —
     * callers treat "empty" as "fall through to the next strategy".
     */
    Optional<LdapAttributes> authenticate(TenantLdapProvider provider, String username, String password);

    /**
     * Test the provider configuration without any user credentials —
     * attempts a service-account bind so an admin can verify config
     * before saving. Returns true on a successful connect+bind.
     */
    boolean testConnection(TenantLdapProvider provider);
}
