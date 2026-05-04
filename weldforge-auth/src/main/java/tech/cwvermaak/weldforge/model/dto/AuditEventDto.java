package tech.cwvermaak.weldforge.model.dto;

import lombok.*;
import tech.cwvermaak.weldforge.model.AuditEvent;

import java.time.LocalDateTime;
import java.util.Map;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuditEventDto {
    private Long id;
    private String tenantSlug;
    private Long actorUserId;
    private String actorEmail;
    private Boolean actorIsSuperAdmin;
    private String eventType;
    private String targetType;
    private String targetId;
    private AuditEvent.Outcome outcome;
    private Map<String, Object> metadata;
    private String ipAddress;
    private String userAgent;
    private LocalDateTime createdAt;

    public static AuditEventDto from(AuditEvent e) {
        return AuditEventDto.builder()
                .id(e.getId())
                .tenantSlug(e.getTenant() != null ? e.getTenant().getSlug() : null)
                .actorUserId(e.getActorUser() != null ? e.getActorUser().getId() : null)
                .actorEmail(e.getActorEmail())
                .actorIsSuperAdmin(e.getActorIsSuperAdmin())
                .eventType(e.getEventType())
                .targetType(e.getTargetType())
                .targetId(e.getTargetId())
                .outcome(e.getOutcome())
                .metadata(e.getMetadata())
                .ipAddress(e.getIpAddress())
                .userAgent(e.getUserAgent())
                .createdAt(e.getCreatedAt())
                .build();
    }
}
