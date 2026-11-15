package tech.cwvermaak.weldforge.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import tech.cwvermaak.weldforge.model.AuditEvent;

/**
 * Searching goes through {@link JpaSpecificationExecutor} so that a filter
 * that is not supplied is simply absent from the SQL. The previous JPQL used
 * {@code (:p is null or ...)} for every optional filter; Postgres cannot type
 * a null bound only inside {@code concat()}, the driver sent it as bytea, and
 * {@code lower(bytea)} failed -- so every search without an actor filter,
 * including the audit page's default load, answered 500.
 */
public interface AuditEventRepository extends JpaRepository<AuditEvent, Long>,
        JpaSpecificationExecutor<AuditEvent> {
}
