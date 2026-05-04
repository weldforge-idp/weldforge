package tech.cwvermaak.weldforge.service.scim;

import lombok.Getter;

/**
 * Tiny SCIM filter parser covering the slice that real-world provisioners
 * actually use. The grammar we recognise:
 *
 * <pre>
 *   filter        := comparison
 *   comparison    := attribute SP "eq" SP value
 *   attribute     := userName | email | externalId | active | id
 *   value         := double-quoted string | true | false
 * </pre>
 *
 * Anything more elaborate (boolean composition with {@code and} / {@code or},
 * {@code co}, {@code sw}, complex value paths) returns {@link ParsedFilter#unsupported()}
 * — the SCIM service then falls back to "return everything" rather than
 * 500ing the client. Real Okta / Workday / Entra payloads are well within
 * this subset; the next pass can grow it without changing the call sites.
 */
public final class ScimFilterParser {

    private ScimFilterParser() {}

    /** Result of parsing a filter expression. */
    @Getter
    public static final class ParsedFilter {
        private final boolean supported;
        private final String attribute;
        private final String stringValue;
        private final Boolean booleanValue;

        private ParsedFilter(boolean supported, String attribute, String stringValue, Boolean booleanValue) {
            this.supported = supported;
            this.attribute = attribute;
            this.stringValue = stringValue;
            this.booleanValue = booleanValue;
        }

        public static ParsedFilter unsupported() {
            return new ParsedFilter(false, null, null, null);
        }
        public static ParsedFilter empty() {
            return new ParsedFilter(true, null, null, null);
        }
        public static ParsedFilter ofString(String attr, String value) {
            return new ParsedFilter(true, attr, value, null);
        }
        public static ParsedFilter ofBoolean(String attr, boolean value) {
            return new ParsedFilter(true, attr, null, value);
        }

        public boolean hasFilter() {
            return supported && attribute != null;
        }
    }

    public static ParsedFilter parse(String filter) {
        if (filter == null || filter.isBlank()) return ParsedFilter.empty();

        String trimmed = filter.trim();

        // Split on whitespace into [attr, op, value, ...]. Most SCIM
        // clients use a single space; tolerate multiple.
        String[] parts = trimmed.split("\\s+", 3);
        if (parts.length < 3) return ParsedFilter.unsupported();

        String attribute = parts[0];
        String op = parts[1];
        String rawValue = parts[2];

        if (!"eq".equalsIgnoreCase(op)) return ParsedFilter.unsupported();

        // Boolean literal
        if ("true".equalsIgnoreCase(rawValue) || "false".equalsIgnoreCase(rawValue)) {
            return ParsedFilter.ofBoolean(attribute, Boolean.parseBoolean(rawValue));
        }

        // Double-quoted string literal
        if (rawValue.length() >= 2
                && rawValue.charAt(0) == '"'
                && rawValue.charAt(rawValue.length() - 1) == '"') {
            String unquoted = rawValue.substring(1, rawValue.length() - 1);
            return ParsedFilter.ofString(attribute, unquoted);
        }

        return ParsedFilter.unsupported();
    }
}
