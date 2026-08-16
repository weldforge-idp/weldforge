package tech.cwvermaak.weldforge.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * B-TEN-3: ServiceProviderConfig must advertise bulk truthfully — the /Bulk
 * endpoint is implemented and capped, so it must report supported=true with the
 * real maxOperations rather than supported=false.
 */
class ScimDiscoveryControllerTest {

    @Test
    @DisplayName("bulk is advertised as supported with the configured maxOperations")
    @SuppressWarnings("unchecked")
    void bulkAdvertisedTruthfully() {
        ScimDiscoveryController controller = new ScimDiscoveryController();
        ReflectionTestUtils.setField(controller, "bulkMaxOperations", 100);

        ResponseEntity<Map<String, Object>> resp =
                controller.serviceProviderConfig("acme", mock(HttpServletRequest.class));

        Map<String, Object> bulk = (Map<String, Object>) resp.getBody().get("bulk");
        assertThat(bulk).containsEntry("supported", true);
        assertThat(bulk).containsEntry("maxOperations", 100);
        assertThat((int) bulk.get("maxPayloadSize")).isGreaterThan(0);
    }
}
