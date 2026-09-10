package tech.cwvermaak.weldforge.config;

import jakarta.persistence.EntityNotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.multipart.MultipartException;
import tech.cwvermaak.weldforge.service.security.PasswordPolicyViolation;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class GlobalExceptionHandlerTest {

    private GlobalExceptionHandler handler;
    private MockHttpServletRequest request;

    @BeforeEach
    void setUp() {
        handler = new GlobalExceptionHandler();
        request = new MockHttpServletRequest("POST", "/api/auth/login");
    }

    @Test
    void notFoundReturns404() {
        ResponseEntity<Map<String, Object>> resp = handler.handleNotFound(
                new EntityNotFoundException("User 42 not found"), request);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(resp.getBody()).containsEntry("error", "not_found");
        assertThat(resp.getBody()).containsKey("timestamp");
        assertThat(resp.getBody()).containsEntry("path", "/api/auth/login");
    }

    @Test
    void badRequestReturns400() {
        ResponseEntity<Map<String, Object>> resp = handler.handleBadRequest(
                new IllegalArgumentException("Email required"), request);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(resp.getBody()).containsEntry("error", "bad_request");
    }

    @Test
    void badCredentialsReturns401() {
        ResponseEntity<Map<String, Object>> resp = handler.handleUnauthorized(
                new BadCredentialsException("Invalid credentials"), request);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(resp.getBody()).containsEntry("error", "unauthorized");
    }

    @Test
    void accessDeniedReturns403() {
        ResponseEntity<Map<String, Object>> resp = handler.handleForbidden(
                new AccessDeniedException("Forbidden"), request);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(resp.getBody()).containsEntry("error", "forbidden");
        assertThat(resp.getBody()).containsEntry("message", "Access denied");
    }

    @Test
    void catchAllReturns500WithoutStackTrace() {
        ResponseEntity<Map<String, Object>> resp = handler.handleAll(
                new RuntimeException("Something broke"), request);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(resp.getBody()).containsEntry("error", "internal_error");
        assertThat(resp.getBody()).containsEntry("message", "An unexpected error occurred");
        assertThat(resp.getBody().get("message").toString()).doesNotContain("Something broke");
    }

    @Test
    void missingRequestParameterReturns400() {
        ResponseEntity<Map<String, Object>> resp = handler.handleMissingParam(
                new MissingServletRequestParameterException("response_type", "String"), request);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(resp.getBody()).containsEntry("error", "missing_parameter");
        assertThat(resp.getBody().get("message").toString()).contains("response_type");
    }

    @Test
    void multipartParseFailureReturns400() {
        ResponseEntity<Map<String, Object>> resp = handler.handleMultipart(
                new MultipartException("Failed to parse multipart servlet request"), request);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(resp.getBody()).containsEntry("error", "malformed_request");
    }

    // ---- CONF-7.3: RFC 9457 on /api/**, legacy elsewhere -------------

    @Test
    void apiErrorIsAProblemDocumentThatKeepsTheLegacyMembers() {
        ResponseEntity<Map<String, Object>> resp = handler.handleValidation(
                validationFailure(), request);

        assertThat(resp.getHeaders().getContentType())
                .isEqualTo(org.springframework.http.MediaType.APPLICATION_PROBLEM_JSON);
        assertThat(resp.getBody())
                .containsEntry("type", "tag:weldforge.org,2026:problem:validation_error")
                .containsEntry("title", "Bad Request")
                .containsEntry("status", 400)
                .containsEntry("instance", "/api/auth/login")
                .containsKey("detail")
                // The admin portal and the Tech Metropolis proxies read these.
                .containsEntry("error", "validation_error")
                .containsKey("message");
        assertThat(resp.getBody().get("detail")).isEqualTo(resp.getBody().get("message"));
    }

    @Test
    void protocolEndpointErrorsKeepTheirLegacyShape() {
        MockHttpServletRequest oauth = new MockHttpServletRequest("GET", "/t/acme/oauth2/authorize");

        ResponseEntity<Map<String, Object>> resp = handler.handleBadRequest(
                new IllegalArgumentException("bad"), oauth);

        assertThat(resp.getHeaders().getContentType()).isNull();
        assertThat(resp.getBody()).containsEntry("error", "bad_request")
                .doesNotContainKeys("type", "title", "status", "detail");
    }

    @Test
    void passwordPolicyProblemCarriesReasonsAsAnExtension() {
        ResponseEntity<Map<String, Object>> resp = handler.handlePasswordPolicy(
                new PasswordPolicyViolation(List.of("at least 12 characters")), request);

        assertThat(resp.getBody())
                .containsEntry("type", "tag:weldforge.org,2026:problem:password_policy")
                .containsEntry("reasons", List.of("at least 12 characters"));
    }

    private static MethodArgumentNotValidException validationFailure() {
        var target = new Object();
        var binding = new org.springframework.validation.BeanPropertyBindingResult(target, "body");
        binding.addError(new org.springframework.validation.FieldError("body", "email", "must not be blank"));
        try {
            var method = GlobalExceptionHandlerTest.class.getDeclaredMethod("validationFailure");
            return new MethodArgumentNotValidException(
                    new org.springframework.core.MethodParameter(method, -1), binding);
        } catch (NoSuchMethodException e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    void passwordPolicyViolationReturns400WithReasons() {
        List<String> reasons = List.of("at least 12 characters", "at least one digit");
        ResponseEntity<Map<String, Object>> resp = handler.handlePasswordPolicy(
                new PasswordPolicyViolation(reasons), request);
        assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(resp.getBody()).containsEntry("error", "password_policy");
        assertThat(resp.getBody().get("message").toString()).contains("at least 12 characters");
        @SuppressWarnings("unchecked")
        List<String> echoed = (List<String>) resp.getBody().get("reasons");
        assertThat(echoed).containsExactlyElementsOf(reasons);
    }
}
