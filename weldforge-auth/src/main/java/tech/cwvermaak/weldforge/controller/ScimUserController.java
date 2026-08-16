package tech.cwvermaak.weldforge.controller;

import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tech.cwvermaak.weldforge.model.dto.scim.ScimErrorDto;
import tech.cwvermaak.weldforge.model.dto.scim.ScimListResponseDto;
import tech.cwvermaak.weldforge.model.dto.scim.ScimPatchRequestDto;
import tech.cwvermaak.weldforge.model.dto.scim.ScimUserDto;
import tech.cwvermaak.weldforge.service.scim.ScimUserService;

/**
 * RFC 7644 Users endpoint. Path-level multi-tenancy: every URL contains
 * the tenant slug, and the SCIM authentication filter has already
 * validated the bearer token belongs to that tenant before this
 * controller is invoked.
 */
@RestController
@RequestMapping(value = "/scim/v2/{slug}/Users", produces = "application/scim+json")
@RequiredArgsConstructor
public class ScimUserController {

    public static final String SCIM_CONTENT_TYPE = "application/scim+json";

    private final ScimUserService scimUserService;

    @GetMapping
    public ResponseEntity<ScimListResponseDto<ScimUserDto>> list(
            @PathVariable String slug,
            @RequestParam(value = "filter", required = false) String filter,
            @RequestParam(value = "startIndex", defaultValue = "1") int startIndex,
            @RequestParam(value = "count", defaultValue = "100") int count,
            HttpServletRequest request) {
        return ResponseEntity.ok(scimUserService.list(filter, startIndex, count, locationBase(request, slug)));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ScimUserDto> get(@PathVariable String slug,
                                           @PathVariable Long id,
                                           HttpServletRequest request) {
        return ResponseEntity.ok(scimUserService.get(id, locationBase(request, slug)));
    }

    @PostMapping(consumes = {SCIM_CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE})
    public ResponseEntity<ScimUserDto> create(@PathVariable String slug,
                                              @RequestBody ScimUserDto incoming,
                                              HttpServletRequest request) {
        ScimUserDto created = scimUserService.create(incoming, locationBase(request, slug));
        return ResponseEntity.status(201).body(created);
    }

    @PutMapping(value = "/{id}",
                consumes = {SCIM_CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE})
    public ResponseEntity<ScimUserDto> replace(@PathVariable String slug,
                                               @PathVariable Long id,
                                               @RequestBody ScimUserDto incoming,
                                               HttpServletRequest request) {
        return ResponseEntity.ok(scimUserService.replace(id, incoming, locationBase(request, slug)));
    }

    @PatchMapping(value = "/{id}",
                  consumes = {SCIM_CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE})
    public ResponseEntity<ScimUserDto> patch(@PathVariable String slug,
                                             @PathVariable Long id,
                                             @RequestBody ScimPatchRequestDto patch,
                                             HttpServletRequest request) {
        return ResponseEntity.ok(scimUserService.patch(id, patch, locationBase(request, slug)));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable String slug, @PathVariable Long id) {
        scimUserService.delete(id);
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

    /**
     * Seat cap reached. RFC 7644 §3.12 defines a closed set of
     * {@code scimType} values and none of them describes a quota, so the
     * field is left off rather than invented; the status and detail carry
     * the meaning.
     */
    @ExceptionHandler(tech.cwvermaak.weldforge.service.SeatLimitExceededException.class)
    public ResponseEntity<ScimErrorDto> handleSeatLimit(
            tech.cwvermaak.weldforge.service.SeatLimitExceededException e) {
        return ResponseEntity.status(409).body(ScimErrorDto.builder()
                .status("409")
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

    private static String locationBase(HttpServletRequest request, String slug) {
        String scheme = request.getScheme();
        String host = request.getServerName();
        int port = request.getServerPort();
        boolean defaultPort = ("http".equals(scheme) && port == 80) || ("https".equals(scheme) && port == 443);
        return scheme + "://" + host + (defaultPort ? "" : ":" + port) + "/scim/v2/" + slug + "/Users";
    }
}
