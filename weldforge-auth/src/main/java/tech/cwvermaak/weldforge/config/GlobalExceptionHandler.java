package tech.cwvermaak.weldforge.config;

import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
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
        String message = ex.getBindingResult().getFieldErrors().stream()
                .map(fe -> fe.getField() + ": " + fe.getDefaultMessage())
                .reduce((a, b) -> a + "; " + b)
                .orElse("Validation failed");
        return respond(HttpStatus.BAD_REQUEST, "validation_error", message, request);
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
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "password_policy");
        body.put("message", ex.getMessage());
        body.put("reasons", ex.getReasons());
        body.put("timestamp", Instant.now().toString());
        body.put("path", request.getRequestURI());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }

    @ExceptionHandler(tech.cwvermaak.weldforge.service.SeatLimitExceededException.class)
    public ResponseEntity<Map<String, Object>> handleSeatLimit(
            tech.cwvermaak.weldforge.service.SeatLimitExceededException ex,
            HttpServletRequest request) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "seat_limit_exceeded");
        body.put("message", ex.getMessage());
        body.put("limit", ex.getLimit());
        body.put("current", ex.getCurrent());
        body.put("timestamp", Instant.now().toString());
        body.put("path", request.getRequestURI());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(body);
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
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", error);
        body.put("message", message);
        body.put("timestamp", Instant.now().toString());
        body.put("path", request.getRequestURI());
        return ResponseEntity.status(status).body(body);
    }
}
