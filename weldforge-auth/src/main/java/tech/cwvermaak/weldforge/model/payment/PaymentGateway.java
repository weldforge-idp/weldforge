package tech.cwvermaak.weldforge.model.payment;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;
import tech.cwvermaak.weldforge.config.crypto.EncryptedStringConverter;
import tech.cwvermaak.weldforge.model.Tenant;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Entity
@Table(name = "payment_gateways")
@Getter @Setter @NoArgsConstructor @AllArgsConstructor @Builder
public class PaymentGateway {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private GatewayScope scope;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private GatewayProvider provider;

    @Column(name = "display_name", nullable = false, length = 128)
    private String displayName;

    @Column(nullable = false)
    @Builder.Default
    private boolean enabled = true;

    @Column(nullable = false)
    @Builder.Default
    private int priority = 0;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "supported_currencies", columnDefinition = "jsonb", nullable = false)
    private List<String> supportedCurrencies;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "supported_countries", columnDefinition = "jsonb")
    private List<String> supportedCountries;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb", nullable = false)
    @Builder.Default
    private Map<String, Object> config = Map.of();

    /**
     * AES-GCM ciphertext. Callers obtain the decoded map via
     * {@code GatewayCredentials.decode()}.
     */
    @Convert(converter = EncryptedStringConverter.class)
    @Column(name = "credentials_encrypted", nullable = false, columnDefinition = "text")
    private String credentialsEncrypted;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "fee_structure", columnDefinition = "jsonb", nullable = false)
    private Map<String, Object> feeStructure;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @PrePersist
    void onCreate() {
        LocalDateTime now = LocalDateTime.now();
        createdAt = now;
        updatedAt = now;
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
