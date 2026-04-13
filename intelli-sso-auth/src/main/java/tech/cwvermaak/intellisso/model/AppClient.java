package tech.cwvermaak.intellisso.model;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "app_clients")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AppClient {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @Column(name = "client_name", nullable = false)
    private String clientName;

    /**
     * API key stays globally unique — it is a secret credential and cross-tenant
     * collisions would be a security risk. The tenant is resolved via the owning
     * {@link Tenant} FK when the key authenticates a request.
     */
    @Column(name = "api_key", unique = true, nullable = false)
    private String apiKey;

    private boolean enabled = true;
}
