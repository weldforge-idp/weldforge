package tech.cwvermaak.weldforge.model;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "responsibilities")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Responsibility {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "role_id", nullable = false)
    private Role role;
}