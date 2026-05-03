package tech.cwvermaak.weldforge.service.scim;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import tech.cwvermaak.weldforge.service.scim.ScimFilterParser.ParsedFilter;

import static org.assertj.core.api.Assertions.assertThat;

class ScimFilterParserTest {

    @Test
    @DisplayName("an empty filter is treated as no filter")
    void emptyFilter() {
        ParsedFilter f = ScimFilterParser.parse(null);
        assertThat(f.isSupported()).isTrue();
        assertThat(f.hasFilter()).isFalse();

        ParsedFilter f2 = ScimFilterParser.parse("");
        assertThat(f2.hasFilter()).isFalse();
    }

    @Test
    @DisplayName("userName eq \"alice@acme.test\" parses cleanly")
    void userNameEq() {
        ParsedFilter f = ScimFilterParser.parse("userName eq \"alice@acme.test\"");
        assertThat(f.hasFilter()).isTrue();
        assertThat(f.getAttribute()).isEqualTo("userName");
        assertThat(f.getStringValue()).isEqualTo("alice@acme.test");
        assertThat(f.getBooleanValue()).isNull();
    }

    @Test
    @DisplayName("active eq true parses as a boolean")
    void activeEqTrue() {
        ParsedFilter f = ScimFilterParser.parse("active eq true");
        assertThat(f.hasFilter()).isTrue();
        assertThat(f.getAttribute()).isEqualTo("active");
        assertThat(f.getBooleanValue()).isTrue();
        assertThat(f.getStringValue()).isNull();
    }

    @Test
    @DisplayName("active eq false parses as a boolean")
    void activeEqFalse() {
        ParsedFilter f = ScimFilterParser.parse("active eq false");
        assertThat(f.hasFilter()).isTrue();
        assertThat(f.getBooleanValue()).isFalse();
    }

    @Test
    @DisplayName("an unsupported operator yields unsupported")
    void coOperatorUnsupported() {
        ParsedFilter f = ScimFilterParser.parse("userName co \"alice\"");
        assertThat(f.isSupported()).isFalse();
        assertThat(f.hasFilter()).isFalse();
    }

    @Test
    @DisplayName("an unquoted value yields unsupported")
    void unquotedValueUnsupported() {
        ParsedFilter f = ScimFilterParser.parse("userName eq alice");
        assertThat(f.isSupported()).isFalse();
    }

    @Test
    @DisplayName("multi-clause filters with `and` are reported unsupported")
    void andUnsupported() {
        // The trailing `and active eq true` makes the value token fail
        // the double-quoted-string check, so the whole filter is rejected
        // as unsupported and the SCIM service falls back to "return all".
        // Documented here so a future relaxation of the parser doesn't
        // accidentally promote a partial parse to "supported".
        ParsedFilter f = ScimFilterParser.parse("userName eq \"alice\" and active eq true");
        assertThat(f.isSupported()).isFalse();
        assertThat(f.hasFilter()).isFalse();
    }

    @Test
    @DisplayName("multi-space input is tolerated")
    void multipleSpacesTolerated() {
        ParsedFilter f = ScimFilterParser.parse("userName    eq    \"alice@acme.test\"");
        assertThat(f.hasFilter()).isTrue();
        assertThat(f.getStringValue()).isEqualTo("alice@acme.test");
    }
}
