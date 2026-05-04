package tech.cwvermaak.weldforge.service.federation;

import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.Option;
import com.jayway.jsonpath.PathNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.UserRepository;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * PRD FED-02 and FED-04.
 *
 * <p>Two responsibilities:
 *
 * <ol>
 *   <li><b>Identity matching</b> — resolve a bag of federated claims to an
 *       existing local user by running the tenant's ordered {@code
 *       matching_rules}. First rule that matches wins. If no rules are
 *       configured the caller falls back to its legacy behaviour (email
 *       lookup).
 *   <li><b>Claim transformation</b> — rewrite incoming claims into the
 *       canonical shape our user model expects using JSONPath expressions,
 *       optionally gated by a condition.
 * </ol>
 *
 * <p>Both inputs are stored as free-form JSONB on the tenant row so they can
 * be edited via the admin API without a redeploy.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class FederationRulesEngine {

    private final UserRepository userRepository;

    private static final Configuration JSONPATH_CFG = Configuration.defaultConfiguration()
            .addOptions(Option.SUPPRESS_EXCEPTIONS, Option.DEFAULT_PATH_LEAF_TO_NULL);

    // ---- Matching ----------------------------------------------------

    /**
     * Walk the tenant's matching rules in order; return the first local
     * user that matches. If the tenant has no rules (common case), returns
     * {@link Optional#empty()} so the caller can fall back to its default.
     */
    public Optional<User> matchUser(Tenant tenant, Map<String, Object> claims) {
        List<Map<String, Object>> rules = tenant.getMatchingRules();
        if (rules == null || rules.isEmpty()) return Optional.empty();

        Long tenantId = tenant.getId();
        for (Map<String, Object> rule : rules) {
            String strategy = stringAt(rule, "strategy");
            String claimKey = stringAt(rule, "claim");
            if (strategy == null || claimKey == null) continue;

            String value = readClaim(claims, claimKey);
            if (value == null || value.isBlank()) continue;

            Optional<User> hit = switch (strategy.toLowerCase(Locale.ROOT)) {
                case "exact_email" ->
                        userRepository.findByTenantIdAndEmailIgnoreCase(tenantId, value.trim());
                case "normalised_email", "normalized_email" ->
                        userRepository.findByTenantIdAndEmailIgnoreCase(
                                tenantId, normaliseEmail(value));
                case "phone" ->
                        userRepository.findByTenantIdAndCellPhoneNumber(
                                tenantId, normalisePhone(value));
                case "external_id" ->
                        userRepository.findByTenantIdAndProviderId(tenantId, value.trim());
                default -> {
                    log.debug("Unknown matching strategy '{}' for tenant {}", strategy, tenantId);
                    yield Optional.empty();
                }
            };
            if (hit.isPresent()) return hit;
        }
        return Optional.empty();
    }

    // ---- Claim transformation ----------------------------------------

    /**
     * Apply the tenant's JSONPath-based claim transforms. Returns a
     * canonicalised claim map keyed by the {@code target} of each rule,
     * leaving the original claims untouched.
     *
     * <p>Rule shape:
     * <pre>
     * {
     *   "target":    "email",
     *   "path":      "$.emails[?(@.primary == true)].value",
     *   "condition": "$.emails[0].verified == true"   // optional
     * }
     * </pre>
     */
    public Map<String, Object> transformClaims(Tenant tenant, Map<String, Object> claims) {
        List<Map<String, Object>> transforms = tenant.getClaimTransforms();
        Map<String, Object> out = new LinkedHashMap<>();
        if (transforms == null || transforms.isEmpty() || claims == null) return out;

        Object document = claims instanceof HashMap<?, ?> ? claims : new HashMap<>(claims);

        for (Map<String, Object> rule : transforms) {
            String target = stringAt(rule, "target");
            String path = stringAt(rule, "path");
            String condition = stringAt(rule, "condition");
            if (target == null || path == null) continue;

            if (condition != null && !evaluateCondition(document, condition)) continue;

            Object value = readJsonPath(document, path);
            if (value == null) continue;

            if (value instanceof List<?> list) {
                if (list.isEmpty()) continue;
                value = list.get(0);
            }
            out.put(target, value);
        }
        return out;
    }

    // ---- Helpers -----------------------------------------------------

    private static String stringAt(Map<String, Object> m, String key) {
        Object v = m == null ? null : m.get(key);
        return v == null ? null : v.toString();
    }

    /**
     * Read a claim by either a dotted path (e.g. {@code profile.email}) or
     * a JSONPath expression (starts with {@code $}). Dotted lookups are the
     * normal case — SAML and OAuth2 attributes are flat.
     */
    private static String readClaim(Map<String, Object> claims, String key) {
        if (claims == null || key == null) return null;
        Object v;
        if (key.startsWith("$")) {
            v = readJsonPath(claims, key);
            if (v instanceof List<?> list) {
                v = list.isEmpty() ? null : list.get(0);
            }
        } else if (key.contains(".")) {
            Object cur = claims;
            for (String seg : key.split("\\.")) {
                if (!(cur instanceof Map<?, ?> map)) {
                    cur = null;
                    break;
                }
                cur = map.get(seg);
            }
            v = cur;
        } else {
            v = claims.get(key);
            if (v instanceof List<?> list && !list.isEmpty()) v = list.get(0);
        }
        return v == null ? null : v.toString();
    }

    private static Object readJsonPath(Object document, String path) {
        try {
            return JsonPath.using(JSONPATH_CFG).parse(document).read(path);
        } catch (PathNotFoundException e) {
            return null;
        } catch (RuntimeException e) {
            log.debug("JSONPath '{}' failed: {}", path, e.getMessage());
            return null;
        }
    }

    private static boolean evaluateCondition(Object document, String condition) {
        // A condition is any JSONPath expression that yields a non-empty,
        // non-false value. Callers can wrap filter predicates with [?(...)]
        // to check attribute shapes before applying a transform.
        Object v = readJsonPath(document, condition);
        if (v == null) return false;
        if (v instanceof Boolean b) return b;
        if (v instanceof List<?> list) return !list.isEmpty();
        if (v instanceof String s) return !s.isEmpty();
        return true;
    }

    private static String normaliseEmail(String email) {
        String trimmed = email.trim().toLowerCase(Locale.ROOT);
        int at = trimmed.indexOf('@');
        if (at < 0) return trimmed;
        String local = trimmed.substring(0, at);
        String domain = trimmed.substring(at);
        // Common gmail-style normalisation: drop +tag and dots in the local part.
        int plus = local.indexOf('+');
        if (plus >= 0) local = local.substring(0, plus);
        if (domain.equals("@gmail.com") || domain.equals("@googlemail.com")) {
            local = local.replace(".", "");
        }
        return local + domain;
    }

    private static String normalisePhone(String phone) {
        StringBuilder sb = new StringBuilder(phone.length());
        for (int i = 0; i < phone.length(); i++) {
            char c = phone.charAt(i);
            if (c == '+' || Character.isDigit(c)) sb.append(c);
        }
        return sb.toString();
    }
}
