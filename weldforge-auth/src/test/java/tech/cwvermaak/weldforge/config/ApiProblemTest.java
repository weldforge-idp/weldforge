package tech.cwvermaak.weldforge.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** CONF-7.3: the one problem-document shape every /api/** error uses. */
class ApiProblemTest {

    private final MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/auth/login");

    @Test
    @DisplayName("The five RFC 9457 members come first, then the legacy ones, all consistent")
    void body_members() {
        Map<String, Object> body = ApiProblem.body(HttpStatus.NOT_FOUND, "not_found", "User 42 not found", request);

        assertThat(body.keySet()).startsWith("type", "title", "status", "detail", "instance");
        assertThat(body)
                .containsEntry("type", "tag:weldforge.org,2026:problem:not_found")
                .containsEntry("title", "Not Found")
                .containsEntry("status", 404)
                .containsEntry("detail", "User 42 not found")
                .containsEntry("instance", "/api/auth/login")
                .containsEntry("error", "not_found")
                .containsEntry("message", "User 42 not found")
                .containsEntry("path", "/api/auth/login")
                .containsKey("timestamp");
    }

    @Test
    @DisplayName("The type URI is stable per code and never varies with the occurrence")
    void type_is_per_code() {
        Object a = ApiProblem.body(HttpStatus.BAD_REQUEST, "bad_request", "one", request).get("type");
        Object b = ApiProblem.body(HttpStatus.BAD_REQUEST, "bad_request", "two",
                new MockHttpServletRequest("GET", "/api/other")).get("type");

        assertThat(a).isEqualTo(b);
    }

    @Test
    @DisplayName("Scope is /api/** only; protocol and page paths keep their own formats")
    void applies_to_api_only() {
        assertThat(ApiProblem.appliesTo(new MockHttpServletRequest("GET", "/api/admin/users"))).isTrue();
        assertThat(ApiProblem.appliesTo(new MockHttpServletRequest("GET", "/api/auth/login"))).isTrue();
        for (String path : List.of("/t/acme/oauth2/token", "/scim/v2/acme/Users", "/saml2/x",
                "/login/", "/apiary", "/health")) {
            assertThat(ApiProblem.appliesTo(new MockHttpServletRequest("GET", path))).as(path).isFalse();
        }
    }

    @Test
    @DisplayName("write() sets the status and problem+json, and the body round-trips as JSON")
    void write_to_servlet_response() throws Exception {
        MockHttpServletResponse response = new MockHttpServletResponse();
        Map<String, Object> body = ApiProblem.body(HttpStatus.FORBIDDEN, "forbidden", "Nope \"quoted\"", request);
        body.put("extra", List.of("a", "b"));

        ApiProblem.write(response, body);

        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getContentType()).startsWith("application/problem+json");
        assertThat(response.getCharacterEncoding()).isEqualToIgnoringCase("UTF-8");
        @SuppressWarnings("unchecked")
        Map<String, Object> parsed = new ObjectMapper().readValue(response.getContentAsString(), Map.class);
        assertThat(parsed)
                .containsEntry("status", 403)
                .containsEntry("detail", "Nope \"quoted\"")
                .containsEntry("extra", List.of("a", "b"));
    }
}
