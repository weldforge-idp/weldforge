package tech.cwvermaak.weldforge.controller;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tech.cwvermaak.weldforge.model.dto.payment.CreateOrderRequest;
import tech.cwvermaak.weldforge.model.dto.payment.CreateOrderResponse;
import tech.cwvermaak.weldforge.service.payment.OrderService;
import tech.cwvermaak.weldforge.service.payment.TierPricing;

/**
 * Browser-facing endpoint the marketing-site order funnel calls. Unlike
 * the admin controllers this is anonymous — it runs without an
 * {@code x-app-authorization} header. CORS is allowed from
 * {@code www.weldforge.org} via {@code CorsProperties}.
 */
@RestController
@RequestMapping("/api/public/orders")
@RequiredArgsConstructor
@Slf4j
public class PublicOrderController {

    private final OrderService orderService;

    @PostMapping
    public ResponseEntity<CreateOrderResponse> create(@Valid @RequestBody CreateOrderRequest req) {
        if (!TierPricing.isKnownTier(req.getTier())) {
            throw new IllegalArgumentException("Unknown tier: " + req.getTier());
        }
        CreateOrderResponse resp = orderService.createOrder(req);
        return ResponseEntity.ok(resp);
    }
}
