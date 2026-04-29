package tech.cwvermaak.intellisso.model;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.util.List;
import java.util.Map;

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

    // EAGER because AppAuthorizationFilter and ScimAuthenticationFilter
    // read tenant.slug / tenant.id outside any @Transactional scope —
    // the filters run ahead of DispatcherServlet and Spring's
    // open-in-view interceptor, so lazy access on the detached entity
    // throws LazyInitializationException. The tenant row is tiny, so
    // the cost of the join is negligible.
    @ManyToOne(fetch = FetchType.EAGER, optional = false)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @Column(name = "client_name", nullable = false)
    private String clientName;

    /**
     * Legacy plaintext key column. New rows leave this NULL — the key is
     * stored as {@link #apiKeyHash} only. Kept for backward compatibility
     * with unrotated keys from before TOK-01.
     */
    @Column(name = "api_key", unique = true)
    private String apiKey;

    /**
     * First 12 chars of the raw key (e.g. {@code wf_live_a1b2}). Shown in
     * the admin UI and audit log so operators can identify a key without
     * being able to use it. PRD TOK-01.
     */
    @Column(name = "api_key_prefix", length = 32)
    private String apiKeyPrefix;

    /** SHA-256(raw key), hex-encoded. PRD TOK-01. */
    @Column(name = "api_key_hash", length = 128)
    private String apiKeyHash;

    /**
     * Optional allow-list of {path, methods} entries. When non-empty a
     * request is rejected unless it matches at least one entry. PRD TOK-02.
     *
     * <p>Shape: {@code [{"path": "/api/admin/users/**", "methods": ["GET","POST"]}]}
     */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "scopes", columnDefinition = "jsonb")
    private List<Map<String, Object>> scopes;

    private boolean enabled = true;
}
