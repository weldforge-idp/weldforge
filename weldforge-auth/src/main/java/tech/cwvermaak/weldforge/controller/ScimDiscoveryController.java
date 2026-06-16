package tech.cwvermaak.weldforge.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import tech.cwvermaak.weldforge.model.dto.scim.ScimListResponseDto;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * RFC 7644 §4 — discovery endpoints. Provisioners hit
 * {@code /ServiceProviderConfig} once at registration time to learn what
 * the server can do, plus {@code /ResourceTypes} and {@code /Schemas}
 * to introspect the supported resources.
 */
@RestController
@RequestMapping(value = "/scim/v2/{slug}", produces = "application/scim+json")
public class ScimDiscoveryController {

    /** Mirrors the cap enforced by {@code ScimBulkController}. */
    @org.springframework.beans.factory.annotation.Value("${app.scim.bulk.max-operations:100}")
    private int bulkMaxOperations;

    @GetMapping("/ServiceProviderConfig")
    public ResponseEntity<Map<String, Object>> serviceProviderConfig(@PathVariable String slug,
                                                                     HttpServletRequest request) {
        Map<String, Object> doc = new LinkedHashMap<>();
        doc.put("schemas", List.of("urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"));
        doc.put("documentationUri", "https://datatracker.ietf.org/doc/html/rfc7644");
        doc.put("patch",     Map.of("supported", true));
        // B-TEN-3: /Bulk is implemented and capped — advertise it truthfully so
        // provisioners honour the real maxOperations instead of being told bulk
        // is unsupported while the endpoint is live.
        doc.put("bulk",      Map.of("supported", true,
                                    "maxOperations", bulkMaxOperations,
                                    "maxPayloadSize", 1048576));
        doc.put("filter",    Map.of("supported", true,  "maxResults", 1000));
        doc.put("changePassword", Map.of("supported", false));
        doc.put("sort",      Map.of("supported", false));
        doc.put("etag",      Map.of("supported", false));
        doc.put("authenticationSchemes", List.of(Map.of(
                "type", "oauthbearertoken",
                "name", "OAuth Bearer Token",
                "description", "Bearer token authenticated against the tenant's WeldForge app client",
                "specUri", "https://datatracker.ietf.org/doc/html/rfc6750",
                "primary", true
        )));
        return ResponseEntity.ok(doc);
    }

    @GetMapping("/ResourceTypes")
    public ResponseEntity<ScimListResponseDto<Map<String, Object>>> resourceTypes(@PathVariable String slug,
                                                                                  HttpServletRequest request) {
        String base = base(request) + "/scim/v2/" + slug;
        Map<String, Object> userType = new LinkedHashMap<>();
        userType.put("schemas", List.of("urn:ietf:params:scim:schemas:core:2.0:ResourceType"));
        userType.put("id", "User");
        userType.put("name", "User");
        userType.put("endpoint", "/Users");
        userType.put("description", "User account");
        userType.put("schema", "urn:ietf:params:scim:schemas:core:2.0:User");
        userType.put("meta", Map.of(
                "location", base + "/ResourceTypes/User",
                "resourceType", "ResourceType"));

        Map<String, Object> groupType = new LinkedHashMap<>();
        groupType.put("schemas", List.of("urn:ietf:params:scim:schemas:core:2.0:ResourceType"));
        groupType.put("id", "Group");
        groupType.put("name", "Group");
        groupType.put("endpoint", "/Groups");
        groupType.put("description", "SCIM Group — set of users");
        groupType.put("schema", "urn:ietf:params:scim:schemas:core:2.0:Group");
        groupType.put("meta", Map.of(
                "location", base + "/ResourceTypes/Group",
                "resourceType", "ResourceType"));

        List<Map<String, Object>> resources = List.of(userType, groupType);
        return ResponseEntity.ok(ScimListResponseDto.<Map<String, Object>>builder()
                .totalResults(resources.size())
                .startIndex(1)
                .itemsPerPage(resources.size())
                .resources(resources)
                .build());
    }

    @GetMapping("/Schemas")
    public ResponseEntity<ScimListResponseDto<Map<String, Object>>> schemas(@PathVariable String slug,
                                                                            HttpServletRequest request) {
        // We expose just enough metadata for Okta / Workday to verify the
        // resource shapes; the full SCIM core schema documents are huge
        // and rarely consulted at runtime.
        Map<String, Object> userSchema = Map.of(
                "id", "urn:ietf:params:scim:schemas:core:2.0:User",
                "name", "User",
                "description", "WeldForge user — see RFC 7643 §4.1",
                "schemas", List.of("urn:ietf:params:scim:schemas:core:2.0:Schema"));
        Map<String, Object> groupSchema = Map.of(
                "id", "urn:ietf:params:scim:schemas:core:2.0:Group",
                "name", "Group",
                "description", "WeldForge group — see RFC 7643 §4.2",
                "schemas", List.of("urn:ietf:params:scim:schemas:core:2.0:Schema"));
        List<Map<String, Object>> resources = List.of(userSchema, groupSchema);
        return ResponseEntity.ok(ScimListResponseDto.<Map<String, Object>>builder()
                .totalResults(resources.size())
                .startIndex(1)
                .itemsPerPage(resources.size())
                .resources(resources)
                .build());
    }

    private static String base(HttpServletRequest request) {
        String scheme = request.getScheme();
        String host = request.getServerName();
        int port = request.getServerPort();
        boolean defaultPort = ("http".equals(scheme) && port == 80) || ("https".equals(scheme) && port == 443);
        return scheme + "://" + host + (defaultPort ? "" : ":" + port);
    }
}
