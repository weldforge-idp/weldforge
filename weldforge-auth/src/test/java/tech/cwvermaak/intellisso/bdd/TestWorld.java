package tech.cwvermaak.intellisso.bdd;

import tech.cwvermaak.intellisso.model.AuditEvent;
import tech.cwvermaak.intellisso.model.MfaFactor;
import tech.cwvermaak.intellisso.model.Role;
import tech.cwvermaak.intellisso.model.ScimGroup;
import tech.cwvermaak.intellisso.model.Tenant;
import tech.cwvermaak.intellisso.model.User;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Shared in-memory world used by the Cucumber step definitions. Each
 * scenario gets a fresh instance (see {@link ScenarioLifecycle}) so state
 * from one scenario cannot leak into the next.
 */
public class TestWorld {

    // Fixtures
    public final Map<String, Tenant> tenants = new HashMap<>();
    public final Map<String, User>   users   = new HashMap<>();
    public final Map<Long, List<MfaFactor>> factorsByUser = new HashMap<>();
    public final Map<String, Role> roles = new HashMap<>();
    public final Map<String, ScimGroup> scimGroups = new HashMap<>();

    // Caller identity for the scenario (simulates the JWT principal + tenant context).
    public User currentActor;

    // Result surfaces
    public Object lastResult;
    public Throwable lastError;
    public int lastRemoved;
    public final List<AuditEvent> auditLog = new ArrayList<>();
    public final List<User> listedUsers = new ArrayList<>();
}
