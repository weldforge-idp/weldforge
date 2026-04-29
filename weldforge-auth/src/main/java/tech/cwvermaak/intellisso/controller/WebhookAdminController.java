package tech.cwvermaak.intellisso.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import tech.cwvermaak.intellisso.model.dto.WebhookSubscriptionDto;
import tech.cwvermaak.intellisso.service.webhook.WebhookSubscriptionService;

import java.util.List;

@RestController
@RequestMapping("/api/admin/webhooks")
@RequiredArgsConstructor
public class WebhookAdminController {

    private final WebhookSubscriptionService service;

    @GetMapping
    public ResponseEntity<List<WebhookSubscriptionDto>> list() {
        return ResponseEntity.ok(service.list());
    }

    @PostMapping
    public ResponseEntity<WebhookSubscriptionDto> create(@RequestBody WebhookSubscriptionDto dto) {
        return ResponseEntity.ok(service.create(dto));
    }

    @PutMapping("/{id}")
    public ResponseEntity<WebhookSubscriptionDto> update(@PathVariable Long id, @RequestBody WebhookSubscriptionDto dto) {
        return ResponseEntity.ok(service.update(id, dto));
    }

    @PostMapping("/{id}/rotate")
    public ResponseEntity<WebhookSubscriptionDto> rotate(@PathVariable Long id) {
        return ResponseEntity.ok(service.rotate(id));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        service.delete(id);
        return ResponseEntity.noContent().build();
    }
}
