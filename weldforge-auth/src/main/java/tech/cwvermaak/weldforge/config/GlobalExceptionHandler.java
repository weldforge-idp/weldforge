package tech.cwvermaak.weldforge.config;

import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MultipartException;
import tech.cwvermaak.weldforge.service.resilience.ProviderUnavailableException;
import tech.cwvermaak.weldforge.service.security.PasswordPolicyViolation;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Consistent error responses across every controller. Stack traces are
 * never leaked — the actual exception is logged at ERROR for the catch-all
 * and at DEBUG for expected client errors.
 *
 * <p>On {@code /api/**} the body is an RFC 9457 problem document
 * ({@link ApiProblem}, CONF-7.3) that still carries the legacy members as
 * extensions. Everywhere else -- the protocol endpoints, whose own specs
 * define their error format -- the legacy shape is unchanged.
 */
@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler(EntityNotFoundException.class)
    public ResponseEntity<Map<String, Object>> handleNotFound(EntityNotFoundException ex,
                                                               HttpServletRequest request) {
        return respond(HttpStatus.NOT_FOUND, "not_found", ex.getMessage(), request);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleBadRequest(IllegalArgumentException ex,
                                                                 HttpServletRequest request) {
        return respond(HttpStatus.BAD_REQUEST, "bad_request", ex.getMessage(), request);
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<Map<String, Object>> handleUnauthorized(BadCredentialsException ex,
                                                                   HttpServletRequest request) {
        return respond(HttpStatus.UNAUTHORIZED, "unauthorized", ex.getMessage(), request);
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<Map<String, Object>> handleForbidden(AccessDeniedException ex,
                                                                HttpServletRequest request) {
        return respond(HttpStatus.FORBIDDEN, "forbidden", "Access denied", request);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidation(MethodArgumentNotValidException ex,
                                                                 HttpServletRequest request) {
        // B-API-2: runs now that a Bean Validation provider is on the
        // classpath. `errors` lists every failing field, so a client can mark
        // each one rather than parse the summary.
        java.util.List<Map<String, String>> errors = ex.getBindingResult().getFieldErrors().stream()
                .map(fe -> Map.of("field", fe.getField(),
                        "message", fe.getDefaultMessage() == null ? "is invalid" : fe.getDefaultMessage()))
                .toList();
        String message = errors.stream()
                .map(e -> e.get("field") + ": " + e.get("message"))
                .reduce((a, b) -> a + "; " + b)
                .orElse("Validation failed");
        return respond(HttpStatus.BAD_REQUEST, "validation_error", message, request,
                Map.of("errors", errors));
    }

    /**
     * A security key's response that failed WebAuthn verification: the
     * client's credential, not our fault.
     */
    @ExceptionHandler({com.yubico.webauthn.exception.RegistrationFailedException.class,
            com.yubico.webauthn.exception.AssertionFailedException.class})
    public ResponseEntity<Map<String, Object>> handleWebAuthn(Exception ex, HttpServletRequest request) {
        log.debug("WebAuthn verification failed on {} {}: {}", request.getMethod(),
                request.getRequestURI(), ex.getMessage());
        return respond(HttpStatus.BAD_REQUEST, "webauthn_failed",
                "The security key's response could not be verified", request);
    }

    /**
     * Safety net for a constraint the request layer did not check (B-API-2):
     * a missing required value is the client's 400, anything else -- a
     * duplicate, a dangling reference -- a 409. Never the SQL or the column.
     */
    @ExceptionHandler(org.springframework.dao.DataIntegrityViolationException.class)
    public ResponseEntity<Map<String, Object>> handleDataIntegrity(
            org.springframework.dao.DataIntegrityViolationException ex, HttpServletRequest request) {
        log.warn("Data integrity violation on {} {} (a validation gap): {}", request.getMethod(),
                request.getRequestURI(), ex.getMostSpecificCause().getMessage());
        if (isMissingValue(ex)) {
            return respond(HttpStatus.BAD_REQUEST, "missing_value",
                    "A required value is missing from the request", request);
        }
        return respond(HttpStatus.CONFLICT, "conflict",
                "The request conflicts with existing data", request);
    }

    private static boolean isMissingValue(Throwable ex) {
        for (Throwable t = ex; t != null; t = t.getCause()) {
            if (t instanceof org.hibernate.PropertyValueException) return true;
            if (t instanceof java.sql.SQLException sql && "23502".equals(sql.getSQLState())) return true;
            if (t.getCause() == t) break;
        }
        return false;
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<Map<String, Object>> handleMissingParam(MissingServletRequestParameterException ex,
                                                                   HttpServletRequest request) {
        return respond(HttpStatus.BAD_REQUEST, "missing_parameter", ex.getMessage(), request);
    }

    @ExceptionHandler(MultipartException.class)
    public ResponseEntity<Map<String, Object>> handleMultipart(MultipartException ex,
                                                                HttpServletRequest request) {
        return respond(HttpStatus.BAD_REQUEST, "malformed_request", ex.getMessage(), request);
    }

    @ExceptionHandler(org.springframework.http.converter.HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, Object>> handleUnreadable(
            org.springframework.http.converter.HttpMessageNotReadableException ex, HttpServletRequest request) {
        // B-API-1: a malformed/unparseable body (e.g. invalid JSON) is a client
        // error, not a server fault — return 400, not the catch-all 500. Generic
        // message: never echo parser internals or the raw payload back.
        log.debug("Unreadable request body on {} {}: {}", request.getMethod(),
                request.getRequestURI(), ex.getMessage());
        return respond(HttpStatus.BAD_REQUEST, "bad_request", "Malformed or unreadable request body", request);
    }

    @ExceptionHandler(PasswordPolicyViolation.class)
    public ResponseEntity<Map<String, Object>> handlePasswordPolicy(PasswordPolicyViolation ex,
                                                                     HttpServletRequest request) {
        return respond(HttpStatus.BAD_REQUEST, "password_policy", ex.getMessage(), request,
                Map.of("reasons", ex.getReasons()));
    }

    @ExceptionHandler(tech.cwvermaak.weldforge.service.SeatLimitExceededException.class)
    public ResponseEntity<Map<String, Object>> handleSeatLimit(
            tech.cwvermaak.weldforge.service.SeatLimitExceededException ex,
            HttpServletRequest request) {
        Map<String, Object> extras = new LinkedHashMap<>();
        extras.put("limit", ex.getLimit());
        extras.put("current", ex.getCurrent());
        return respond(HttpStatus.CONFLICT, "seat_limit_exceeded", ex.getMessage(), request, extras);
    }

    @ExceptionHandler(ProviderUnavailableException.class)
    public ResponseEntity<Map<String, Object>> handleProviderUnavailable(ProviderUnavailableException ex,
                                                                          HttpServletRequest request) {
        log.warn("Provider {} unavailable on {} {}: {}", ex.getProvider(),
                request.getMethod(), request.getRequestURI(), ex.getMessage());
        return respond(HttpStatus.SERVICE_UNAVAILABLE, "provider_unavailable", ex.getMessage(), request);
    }

    @ExceptionHandler(org.springframework.web.HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<Map<String, Object>> handleMethodNotAllowed(
            org.springframework.web.HttpRequestMethodNotSupportedException ex, HttpServletRequest request) {
        return respond(HttpStatus.METHOD_NOT_ALLOWED, "method_not_allowed",
                "HTTP " + ex.getMethod() + " is not supported for this endpoint", request);
    }

    @ExceptionHandler(org.springframework.web.servlet.resource.NoResourceFoundException.class)
    public ResponseEntity<Map<String, Object>> handleNoResource(
            org.springframework.web.servlet.resource.NoResourceFoundException ex, HttpServletRequest request) {
        return respond(HttpStatus.NOT_FOUND, "not_found", ex.getMessage(), request);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleAll(Exception ex, HttpServletRequest request) {
        log.error("Unhandled exception on {} {}: {}", request.getMethod(), request.getRequestURI(),
                ex.getMessage(), ex);
        return respond(HttpStatus.INTERNAL_SERVER_ERROR, "internal_error",
                "An unexpected error occurred", request);
    }

    private static ResponseEntity<Map<String, Object>> respond(HttpStatus status, String error,
                                                                String message, HttpServletRequest request) {
        return respond(status, error, message, request, Map.of());
    }

    private static ResponseEntity<Map<String, Object>> respond(HttpStatus status, String error,
                                                                String message, HttpServletRequest request,
                                                                Map<String, Object> extras) {
        if (ApiProblem.appliesTo(request)) {
            Map<String, Object> body = ApiProblem.body(status, error, message, request);
            body.putAll(extras);
            // Set explicitly, so a client's Accept: application/json does not
            // negotiate it away -- problem+json is what RFC 9457 requires.
            return ResponseEntity.status(status)
                    .contentType(MediaType.APPLICATION_PROBLEM_JSON)
                    .body(body);
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", error);
        body.put("message", message);
        body.putAll(extras);
        body.put("timestamp", Instant.now().toString());
        body.put("path", request.getRequestURI());
        return ResponseEntity.status(status).body(body);
    }
}
