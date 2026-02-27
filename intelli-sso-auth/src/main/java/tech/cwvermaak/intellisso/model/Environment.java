package tech.cwvermaak.intellisso.model;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "environments")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Environment {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name;          // e.g. dev, staging, prod

    @Column(name = "project_name")
    private String projectName;

    private String description;
}