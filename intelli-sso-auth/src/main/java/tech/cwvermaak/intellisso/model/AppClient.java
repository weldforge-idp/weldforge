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

    @Column(name = "client_name", nullable = false)
    private String clientName;

    @Column(name = "api_key", unique = true, nullable = false)
    private String apiKey;

    private boolean enabled = true;
}