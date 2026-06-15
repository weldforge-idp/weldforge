package tech.cwvermaak.weldforge.controller;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.TenantSigningKey;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.TenantRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;
import tech.cwvermaak.weldforge.service.oidc.TenantSigningKeyService;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * OIDC userinfo endpoint. Verifies the bearer access token against the
 * tenant's published signing key, then returns claims from the user row.
 */
@RestController
@RequiredArgsConstructor
public class OidcUserinfoController {

    private final TenantRepository tenantRepository;
    private final UserRepository userRepository;
    private final TenantSigningKeyService signingKeyService;

    @GetMapping("/t/{slug}/oauth2/userinfo")
    public ResponseEntity<Map<String, Object>> userinfo(@PathVariable String slug,
                                                        HttpServletRequest request) {
        Tenant tenant = tenantRepository.findBySlug(slug)
                .orElseThrow(() -> new EntityNotFoundException("Unknown tenant"));

        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            return ResponseEntity.status(401).build();
        }
        String token = header.substring(7);

        Claims claims;
        try {
            // The key locator reads the kid from the JWS header and returns
            // the matching tenant public key, so a single parse both verifies
            // the signature and yields the claims.
            claims = Jwts.parser()
                    .keyLocator(jws -> {
                        TenantSigningKey row = signingKeyService.requireByKid(jws.get("kid").toString());
                        return signingKeyService.loadPublicKey(row);
                    })
                    .clockSkewSeconds(60)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (JwtException | IllegalArgumentException e) {
            return ResponseEntity.status(401).build();
        }

        // The token must have been issued for *this* tenant.
        Object iss = claims.get("iss");
        if (iss == null || !iss.toString().endsWith("/t/" + tenant.getSlug())) {
            return ResponseEntity.status(401).build();
        }

        Long userId;
        try {
            userId = Long.valueOf(claims.getSubject());
        } catch (NumberFormatException e) {
            return ResponseEntity.status(401).build();
        }
        User user = userRepository.findById(userId).orElse(null);
        if (user == null || !user.getTenant().getId().equals(tenant.getId())) {
            return ResponseEntity.status(401).build();
        }

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("sub", String.valueOf(user.getId()));
        body.put("email", user.getEmail());
        if (user.getName() != null) body.put("name", user.getName());
        if (user.getImageUrl() != null) body.put("picture", user.getImageUrl());
        return ResponseEntity.ok(body);
    }
}
