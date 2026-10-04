package tech.cwvermaak.weldforge.controller;

import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * The OIDC {@code prompt} parameter: a SPACE-DELIMITED, case-sensitive list
 * of values (OIDC Core §3.1.2.1), not a single token.
 *
 * <p>It was previously compared with {@code "none".equals(prompt)}, which is
 * right for the common single-value case and silently wrong for every other:
 * {@code prompt=consent none} would have been treated as neither, quietly
 * ignoring both a forbidden-interaction instruction and a consent
 * instruction. A relying party asking for two things and getting neither,
 * with a 200, is the failure mode this whole class exists to remove.
 */
public final class OidcPrompt {

    public static final String NONE = "none";
    public static final String LOGIN = "login";
    public static final String CONSENT = "consent";
    public static final String SELECT_ACCOUNT = "select_account";

    private final Set<String> values;

    private OidcPrompt(Set<String> values) {
        this.values = values;
    }

    /** Parse the raw parameter; null or blank yields an empty set. */
    public static OidcPrompt parse(String raw) {
        if (raw == null || raw.isBlank()) {
            return new OidcPrompt(Set.of());
        }
        return new OidcPrompt(new LinkedHashSet<>(
                Arrays.stream(raw.trim().split("\\s+"))
                        .filter(v -> !v.isBlank())
                        .toList()));
    }

    public boolean has(String value) {
        return values.contains(value);
    }

    public boolean isEmpty() {
        return values.isEmpty();
    }

    /**
     * {@code none} may not be combined with any other value — asking the
     * server both to never interact and to force an interaction is a
     * contradiction, and §3.1.2.1 makes it an {@code invalid_request} rather
     * than letting the server pick a winner.
     */
    public boolean noneCombinedWithOthers() {
        return values.contains(NONE) && values.size() > 1;
    }

    /**
     * Whether the request demands a fresh authentication.
     *
     * <p>{@code select_account} is grouped with {@code login} deliberately.
     * A session here holds exactly one account, so the only way to offer a
     * choice is to return the user to the sign-in form — which is also what
     * satisfies the request when they pick the same account again. The
     * alternative, {@code account_selection_required}, would refuse a request
     * we are in fact able to honour.
     */
    public boolean requiresReauthentication() {
        return values.contains(LOGIN) || values.contains(SELECT_ACCOUNT);
    }

    @Override
    public String toString() {
        return String.join(" ", values);
    }
}
