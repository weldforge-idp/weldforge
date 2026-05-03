package tech.cwvermaak.weldforge.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tech.cwvermaak.weldforge.model.dto.scim.*;
import tech.cwvermaak.weldforge.service.scim.ScimGroupService;
import tech.cwvermaak.weldforge.service.scim.ScimUserService;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * RFC 7644 section 3.7 — SCIM Bulk Operations endpoint.
 * Processes an array of SCIM operations (POST/PUT/PATCH/DELETE)
 * against Users and Groups sequentially and returns aggregated results.
 */
@RestController
@RequestMapping(value = "/scim/v2/{slug}/Bulk", produces = "application/scim+json")
@RequiredArgsConstructor
@Slf4j
public class ScimBulkController {

    public static final String SCIM_CONTENT_TYPE = "application/scim+json";

    private static final Pattern USERS_PATH = Pattern.compile("^/Users(?:/(\\d+))?$");
    private static final Pattern GROUPS_PATH = Pattern.compile("^/Groups(?:/(\\d+))?$");

    private final ScimUserService scimUserService;
    private final ScimGroupService scimGroupService;
    private final ObjectMapper objectMapper;

    @Value("${app.scim.bulk.max-operations:100}")
    private int maxOperations;

    @PostMapping(consumes = {SCIM_CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE})
    public ResponseEntity<ScimBulkResponseDto> bulk(
            @PathVariable String slug,
            @RequestBody ScimBulkRequestDto request,
            HttpServletRequest httpRequest) {

        if (request.getOperations() == null || request.getOperations().isEmpty()) {
            return ResponseEntity.ok(ScimBulkResponseDto.builder()
                    .operations(List.of())
                    .build());
        }

        if (request.getOperations().size() > maxOperations) {
            ScimBulkResponseDto.BulkOperationResponse error = ScimBulkResponseDto.BulkOperationResponse.builder()
                    .status("413")
                    .response(ScimErrorDto.builder()
                            .status("413")
                            .scimType("tooMany")
                            .detail("Bulk request exceeds maximum of " + maxOperations + " operations")
                            .build())
                    .build();
            return ResponseEntity.status(413).body(ScimBulkResponseDto.builder()
                    .operations(List.of(error))
                    .build());
        }

        String userLocationBase = locationBase(httpRequest, slug, "Users");
        String groupLocationBase = locationBase(httpRequest, slug, "Groups");

        List<ScimBulkResponseDto.BulkOperationResponse> results = new ArrayList<>();

        for (ScimBulkRequestDto.BulkOperation op : request.getOperations()) {
            results.add(processOperation(op, userLocationBase, groupLocationBase));
        }

        return ResponseEntity.ok(ScimBulkResponseDto.builder()
                .operations(results)
                .build());
    }

    private ScimBulkResponseDto.BulkOperationResponse processOperation(
            ScimBulkRequestDto.BulkOperation op,
            String userLocationBase,
            String groupLocationBase) {
        try {
            String method = op.getMethod() != null ? op.getMethod().toUpperCase() : "";
            String path = op.getPath();

            if (path == null || path.isBlank()) {
                return errorResponse(op, "400", "invalidValue", "path is required");
            }

            Matcher userMatcher = USERS_PATH.matcher(path);
            Matcher groupMatcher = GROUPS_PATH.matcher(path);

            if (userMatcher.matches()) {
                return processUserOperation(op, method, userMatcher.group(1), userLocationBase);
            } else if (groupMatcher.matches()) {
                return processGroupOperation(op, method, groupMatcher.group(1),
                        groupLocationBase, userLocationBase);
            } else {
                return errorResponse(op, "400", "invalidPath",
                        "Unsupported path: " + path + ". Supported: /Users, /Groups");
            }
        } catch (Exception e) {
            log.warn("Bulk operation failed: method={} path={} error={}",
                    op.getMethod(), op.getPath(), e.getMessage());
            return errorResponse(op, "500", "internalError", e.getMessage());
        }
    }

    private ScimBulkResponseDto.BulkOperationResponse processUserOperation(
            ScimBulkRequestDto.BulkOperation op, String method, String idStr,
            String userLocationBase) {

        return switch (method) {
            case "POST" -> {
                ScimUserDto userDto = convertData(op.getData(), ScimUserDto.class);
                ScimUserDto created = scimUserService.create(userDto, userLocationBase);
                yield ScimBulkResponseDto.BulkOperationResponse.builder()
                        .method(method)
                        .bulkId(op.getBulkId())
                        .status("201")
                        .location(userLocationBase + "/" + created.getId())
                        .response(created)
                        .build();
            }
            case "PUT" -> {
                Long id = requireId(idStr, "PUT /Users requires an id");
                ScimUserDto userDto = convertData(op.getData(), ScimUserDto.class);
                ScimUserDto replaced = scimUserService.replace(id, userDto, userLocationBase);
                yield ScimBulkResponseDto.BulkOperationResponse.builder()
                        .method(method)
                        .bulkId(op.getBulkId())
                        .status("200")
                        .location(userLocationBase + "/" + id)
                        .response(replaced)
                        .build();
            }
            case "PATCH" -> {
                Long id = requireId(idStr, "PATCH /Users requires an id");
                ScimPatchRequestDto patch = convertData(op.getData(), ScimPatchRequestDto.class);
                ScimUserDto patched = scimUserService.patch(id, patch, userLocationBase);
                yield ScimBulkResponseDto.BulkOperationResponse.builder()
                        .method(method)
                        .bulkId(op.getBulkId())
                        .status("200")
                        .location(userLocationBase + "/" + id)
                        .response(patched)
                        .build();
            }
            case "DELETE" -> {
                Long id = requireId(idStr, "DELETE /Users requires an id");
                scimUserService.delete(id);
                yield ScimBulkResponseDto.BulkOperationResponse.builder()
                        .method(method)
                        .bulkId(op.getBulkId())
                        .status("204")
                        .build();
            }
            default -> errorResponse(op, "400", "invalidValue",
                    "Unsupported method for /Users: " + method);
        };
    }

    private ScimBulkResponseDto.BulkOperationResponse processGroupOperation(
            ScimBulkRequestDto.BulkOperation op, String method, String idStr,
            String groupLocationBase, String userLocationBase) {

        return switch (method) {
            case "POST" -> {
                ScimGroupDto groupDto = convertData(op.getData(), ScimGroupDto.class);
                ScimGroupDto created = scimGroupService.create(groupDto, groupLocationBase, userLocationBase);
                yield ScimBulkResponseDto.BulkOperationResponse.builder()
                        .method(method)
                        .bulkId(op.getBulkId())
                        .status("201")
                        .location(groupLocationBase + "/" + created.getId())
                        .response(created)
                        .build();
            }
            case "PUT" -> {
                Long id = requireId(idStr, "PUT /Groups requires an id");
                ScimGroupDto groupDto = convertData(op.getData(), ScimGroupDto.class);
                ScimGroupDto replaced = scimGroupService.replace(id, groupDto, groupLocationBase, userLocationBase);
                yield ScimBulkResponseDto.BulkOperationResponse.builder()
                        .method(method)
                        .bulkId(op.getBulkId())
                        .status("200")
                        .location(groupLocationBase + "/" + id)
                        .response(replaced)
                        .build();
            }
            case "PATCH" -> {
                Long id = requireId(idStr, "PATCH /Groups requires an id");
                ScimPatchRequestDto patch = convertData(op.getData(), ScimPatchRequestDto.class);
                ScimGroupDto patched = scimGroupService.patch(id, patch, groupLocationBase, userLocationBase);
                yield ScimBulkResponseDto.BulkOperationResponse.builder()
                        .method(method)
                        .bulkId(op.getBulkId())
                        .status("200")
                        .location(groupLocationBase + "/" + id)
                        .response(patched)
                        .build();
            }
            case "DELETE" -> {
                Long id = requireId(idStr, "DELETE /Groups requires an id");
                scimGroupService.delete(id);
                yield ScimBulkResponseDto.BulkOperationResponse.builder()
                        .method(method)
                        .bulkId(op.getBulkId())
                        .status("204")
                        .build();
            }
            default -> errorResponse(op, "400", "invalidValue",
                    "Unsupported method for /Groups: " + method);
        };
    }

    private <T> T convertData(Map<String, Object> data, Class<T> type) {
        if (data == null) {
            throw new IllegalArgumentException("data is required for this operation");
        }
        return objectMapper.convertValue(data, type);
    }

    private static Long requireId(String idStr, String message) {
        if (idStr == null || idStr.isBlank()) {
            throw new IllegalArgumentException(message);
        }
        try {
            return Long.valueOf(idStr);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("Invalid id: " + idStr);
        }
    }

    private static ScimBulkResponseDto.BulkOperationResponse errorResponse(
            ScimBulkRequestDto.BulkOperation op, String status, String scimType, String detail) {
        return ScimBulkResponseDto.BulkOperationResponse.builder()
                .method(op.getMethod())
                .bulkId(op.getBulkId())
                .status(status)
                .response(ScimErrorDto.builder()
                        .status(status)
                        .scimType(scimType)
                        .detail(detail)
                        .build())
                .build();
    }

    private static String locationBase(HttpServletRequest request, String slug, String resource) {
        String scheme = request.getScheme();
        String host = request.getServerName();
        int port = request.getServerPort();
        boolean defaultPort = ("http".equals(scheme) && port == 80) || ("https".equals(scheme) && port == 443);
        String base = scheme + "://" + host + (defaultPort ? "" : ":" + port);
        return base + "/scim/v2/" + slug + "/" + resource;
    }
}
