package tech.cwvermaak.intellisso.controller;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tech.cwvermaak.intellisso.model.payment.GatewayProvider;
import tech.cwvermaak.intellisso.service.payment.WebhookService;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Receives webhooks from the payment gateways. One path per provider
 * lets us route to the right {@link WebhookService} dispatcher and
 * also makes it easy to correlate a noisy delivery pattern to a
 * specific provider in the logs.
 *
 * <p>Endpoints are anonymous — signature verification is the auth.
 */
@RestController
@RequestMapping("/api/webhooks")
@RequiredArgsConstructor
@Slf4j
public class WebhookController {

    private final WebhookService webhookService;

    @PostMapping("/stripe")
    public ResponseEntity<String> stripe(HttpServletRequest request,
                                          @RequestHeader(value = "Stripe-Signature", required = false) String signature)
            throws IOException {
        // Stripe's signature is HMAC over the EXACT raw body. Binding via
        // @RequestBody into a String works in practice because Spring does
        // not transform the UTF-8 octets, but reading the servlet stream is
        // the belt-and-braces path and isolates us from any body filter.
        byte[] raw = request.getInputStream().readAllBytes();
        String rawBody = raw == null ? "" : new String(raw, StandardCharsets.UTF_8);
        return dispatch(GatewayProvider.STRIPE, rawBody, signature);
    }

    @PostMapping("/paddle")
    public ResponseEntity<String> paddle(@RequestBody String rawBody,
                                          @RequestHeader(value = "Paddle-Signature", required = false) String signature) {
        return dispatch(GatewayProvider.PADDLE, rawBody, signature);
    }

    @PostMapping("/payfast")
    public ResponseEntity<String> payfast(@RequestBody String rawBody,
                                           @RequestHeader(value = "X-PayFast-Signature", required = false) String signature) {
        return dispatch(GatewayProvider.PAYFAST, rawBody, signature);
    }

    @PostMapping("/yoco")
    public ResponseEntity<String> yoco(@RequestBody String rawBody,
                                        @RequestHeader(value = "X-Yoco-Signature", required = false) String signature) {
        return dispatch(GatewayProvider.YOCO, rawBody, signature);
    }

    private ResponseEntity<String> dispatch(GatewayProvider provider, String rawBody, String signature) {
        WebhookService.Result result = webhookService.handle(provider, rawBody, signature);
        return switch (result) {
            case ACCEPTED, IGNORED -> ResponseEntity.ok("ok");
            case SIGNATURE_INVALID -> ResponseEntity.status(HttpStatus.BAD_REQUEST).body("bad signature");
            case BAD_PROVIDER, NO_GATEWAY_CONFIGURED -> ResponseEntity.status(HttpStatus.NOT_FOUND).body("no gateway");
            case NO_MATCHING_ORDER -> ResponseEntity.status(HttpStatus.NOT_FOUND).body("no matching order");
        };
    }
}
