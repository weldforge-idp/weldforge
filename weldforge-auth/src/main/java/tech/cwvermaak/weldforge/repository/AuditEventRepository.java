package tech.cwvermaak.weldforge.repository;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import tech.cwvermaak.weldforge.model.AuditEvent;

import java.time.LocalDateTime;

public interface AuditEventRepository extends JpaRepository<AuditEvent, Long> {

    @Query("""
        select e from AuditEvent e
        where (:tenantId is null or e.tenant.id = :tenantId)
          and (:eventType is null or e.eventType = :eventType)
          and (:actorEmail is null or lower(e.actorEmail) like lower(concat('%', :actorEmail, '%')))
          and (:since is null or e.createdAt >= :since)
          and (:until is null or e.createdAt <  :until)
        order by e.createdAt desc
        """)
    Page<AuditEvent> search(@Param("tenantId")   Long tenantId,
                            @Param("eventType") String eventType,
                            @Param("actorEmail") String actorEmail,
                            @Param("since")     LocalDateTime since,
                            @Param("until")     LocalDateTime until,
                            Pageable pageable);
}
