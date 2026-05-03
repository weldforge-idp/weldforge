package tech.cwvermaak.weldforge.controller;

import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tech.cwvermaak.weldforge.model.dto.scim.ScimErrorDto;
import tech.cwvermaak.weldforge.model.dto.scim.ScimGroupDto;
import tech.cwvermaak.weldforge.model.dto.scim.ScimListResponseDto;
import tech.cwvermaak.weldforge.model.dto.scim.ScimPatchRequestDto;
import tech.cwvermaak.weldforge.service.scim.ScimGroupService;

/**
 * RFC 7644 Groups endpoint, mirroring {@link ScimUserController} for the
 * Group resource type. Tenant scoping is enforced by the SCIM
 * authentication filter (the URL slug must match the api key's tenant)
 * plus the service layer ({@code TenantAccessor.requireTenantId}).
 */
@RestController
@RequestMapping(value = "/scim/v2/{slug}/Groups", produces = "application/scim+json")
@RequiredArgsConstructor
public class ScimGroupController {

    public static final String SCIM_CONTENT_TYPE = "application/scim+json";

    private final ScimGroupService scimGroupService;

    @GetMapping
    public ResponseEntity<ScimListResponseDto<ScimGroupDto>> list(
            @PathVariable String slug,
            @RequestParam(value = "filter", required = false) String filter,
            @RequestParam(value = "startIndex", defaultValue = "1") int startIndex,
            @RequestParam(value = "count", defaultValue = "100") int count,
            HttpServletRequest request) {
        return ResponseEntity.ok(scimGroupService.list(filter, startIndex, count,
                groupLocationBase(request, slug), userLocationBase(request, slug)));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ScimGroupDto> get(@PathVariable String slug,
                                            @PathVariable Long id,
                                            HttpServletRequest request) {
        return ResponseEntity.ok(scimGroupService.get(id,
                groupLocationBase(request, slug), userLocationBase(request, slug)));
    }

    @PostMapping(consumes = {SCIM_CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE})
    public ResponseEntity<ScimGroupDto> create(@PathVariable String slug,
                                               @RequestBody ScimGroupDto incoming,
                                               HttpServletRequest request) {
        ScimGroupDto created = scimGroupService.create(incoming,
                groupLocationBase(request, slug), userLocationBase(request, slug));
        return ResponseEntity.status(201).body(created);
    }

    @PutMapping(value = "/{id}",
                consumes = {SCIM_CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE})
    public ResponseEntity<ScimGroupDto> replace(@PathVariable String slug,
                                                @PathVariable Long id,
                                                @RequestBody ScimGroupDto incoming,
                                                HttpServletRequest request) {
        return ResponseEntity.ok(scimGroupService.replace(id, incoming,
                groupLocationBase(request, slug), userLocationBase(request, slug)));
    }

    @PatchMapping(value = "/{id}",
                  consumes = {SCIM_CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE})
    public ResponseEntity<ScimGroupDto> patch(@PathVariable String slug,
                                              @PathVariable Long id,
                                              @RequestBody ScimPatchRequestDto patch,
                                              HttpServletRequest request) {
        return ResponseEntity.ok(scimGroupService.patch(id, patch,
                groupLocationBase(request, slug), userLocationBase(request, slug)));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable String slug, @PathVariable Long id) {
        scimGroupService.delete(id);
        return ResponseEntity.noContent().build();
    }

    @ExceptionHandler(EntityNotFoundException.class)
    public ResponseEntity<ScimErrorDto> handleNotFound(EntityNotFoundException e) {
        return ResponseEntity.status(404).body(ScimErrorDto.builder()
                .status("404")
                .scimType("notFound")
                .detail(e.getMessage())
                .build());
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ScimErrorDto> handleBadRequest(IllegalArgumentException e) {
        return ResponseEntity.status(400).body(ScimErrorDto.builder()
                .status("400")
                .scimType("invalidValue")
                .detail(e.getMessage())
                .build());
    }

    private static String groupLocationBase(HttpServletRequest request, String slug) {
        return base(request) + "/scim/v2/" + slug + "/Groups";
    }

    private static String userLocationBase(HttpServletRequest request, String slug) {
        return base(request) + "/scim/v2/" + slug + "/Users";
    }

    private static String base(HttpServletRequest request) {
        String scheme = request.getScheme();
        String host = request.getServerName();
        int port = request.getServerPort();
        boolean defaultPort = ("http".equals(scheme) && port == 80) || ("https".equals(scheme) && port == 443);
        return scheme + "://" + host + (defaultPort ? "" : ":" + port);
    }
}
