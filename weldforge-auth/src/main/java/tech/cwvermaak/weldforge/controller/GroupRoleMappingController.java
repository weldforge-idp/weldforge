package tech.cwvermaak.weldforge.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tech.cwvermaak.weldforge.model.dto.GroupRoleMappingDto;
import tech.cwvermaak.weldforge.service.GroupRoleMappingService;

import java.util.List;

/**
 * Admin CRUD for group-to-role mappings. Mappings are immutable —
 * delete and re-create to change priority.
 */
@RestController
@RequestMapping("/api/admin/group-role-mappings")
@RequiredArgsConstructor
public class GroupRoleMappingController {

    private final GroupRoleMappingService mappingService;

    @GetMapping
    public ResponseEntity<List<GroupRoleMappingDto>> list() {
        return ResponseEntity.ok(mappingService.list());
    }

    @PostMapping
    public ResponseEntity<GroupRoleMappingDto> create(@RequestBody GroupRoleMappingDto dto) {
        return ResponseEntity.ok(mappingService.create(dto));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        mappingService.delete(id);
        return ResponseEntity.noContent().build();
    }
}
