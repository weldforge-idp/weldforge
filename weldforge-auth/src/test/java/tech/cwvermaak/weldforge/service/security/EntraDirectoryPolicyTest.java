package tech.cwvermaak.weldforge.service.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import tech.cwvermaak.weldforge.model.SocialProviderType;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("Entra ID directory allow-list (WF-4)")
class EntraDirectoryPolicyTest {

    private static final String A = "11111111-2222-3333-4444-555555555555";
    private static final String B = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

    @Test
    @DisplayName("stored values are lower-cased, de-duplicated and space-separated")
    void normalises() {
        assertThat(EntraDirectoryPolicy.normalise(SocialProviderType.MICROSOFT, A.toUpperCase() + ", " + B + " " + A))
                .isEqualTo(A + " " + B);
    }

    @Test
    @DisplayName("blank clears the list")
    void blankIsNone() {
        assertThat(EntraDirectoryPolicy.normalise(SocialProviderType.MICROSOFT, "  ")).isNull();
        assertThat(EntraDirectoryPolicy.normalise(SocialProviderType.GOOGLE, null)).isNull();
    }

    @Test
    @DisplayName("a domain name is refused: it would silently lock everyone out")
    void domainNameRefused() {
        assertThatThrownBy(() -> EntraDirectoryPolicy.normalise(SocialProviderType.MICROSOFT, "acme.onmicrosoft.com"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("GUID");
    }

    @Test
    @DisplayName("only a Microsoft provider takes a list")
    void otherProvidersRefused() {
        assertThatThrownBy(() -> EntraDirectoryPolicy.normalise(SocialProviderType.GOOGLE, A))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("permits: no list admits anyone, a list demands a listed tid")
    void permits() {
        assertThat(EntraDirectoryPolicy.permits(null, null)).isTrue();
        assertThat(EntraDirectoryPolicy.permits(A, A.toUpperCase())).isTrue();
        assertThat(EntraDirectoryPolicy.permits(A, B)).isFalse();
        assertThat(EntraDirectoryPolicy.permits(A, null)).isFalse();
    }
}
