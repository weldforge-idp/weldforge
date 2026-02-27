package tech.cwvermaak.intellisso.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import tech.cwvermaak.intellisso.model.Role;
import tech.cwvermaak.intellisso.model.dto.RoleDto;
import tech.cwvermaak.intellisso.repository.RoleRepository;

import java.util.List;

@Service
@RequiredArgsConstructor
public class AdminService {

    private final RoleRepository roleRepository;

    public Role createRole(RoleDto dto) {
        if (dto.getName() == null || dto.getName().trim().isEmpty()) {
            throw new IllegalArgumentException("Role name cannot be empty");
        }

        Role role = Role.builder()
                .name(dto.getName().trim())
                .description(dto.getDescription())
                .build();

        return roleRepository.save(role);
    }

    public List<Role> getAllRoles() {
        return roleRepository.findAll();
    }

    // Add update/delete methods as needed
}