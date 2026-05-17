package tech.cwvermaak.weldforge.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tech.cwvermaak.weldforge.model.dto.AdminMembershipDto;
import tech.cwvermaak.weldforge.service.AdminMembershipService;

import java.util.List;

/**
 * Admin membership management — cross-tenant-admin-spec.md §6.2.
 *
 * All three operations require global {@code SUPER_ADMIN} scope, enforced in
 * {@link AdminMembershipService}.
 */
@RestController
@RequestMapping("/api/admin/users/{userId}/memberships")
@RequiredArgsConstructor
public class AdminMembershipController {

    private final AdminMembershipService membershipService;

    @GetMapping
    public ResponseEntity<List<AdminMembershipDto>> list(@PathVariable Long userId) {
        return ResponseEntity.ok(membershipService.list(userId));
    }

    /** Grant a membership. {@code tenantId} null in the body grants a global membership. */
    @PostMapping
    public ResponseEntity<AdminMembershipDto> grant(@PathVariable Long userId,
                                                    @RequestBody AdminMembershipDto request) {
        return ResponseEntity.ok(membershipService.grant(userId, request));
    }

    @DeleteMapping("/{membershipId}")
    public ResponseEntity<Void> revoke(@PathVariable Long userId,
                                       @PathVariable Long membershipId) {
        membershipService.revoke(userId, membershipId);
        return ResponseEntity.noContent().build();
    }
}
