package tech.cwvermaak.intellisso.service.oidc;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tech.cwvermaak.intellisso.model.Tenant;
import tech.cwvermaak.intellisso.model.TenantSigningKey;
import tech.cwvermaak.intellisso.repository.TenantSigningKeyRepository;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Owns the per-tenant RSA keypairs the OIDC issuer signs tokens with.
 *
 * On first use the service generates a 2048-bit RSA key, persists the
 * private half encrypted at rest via {@code EncryptedStringConverter}, and
 * exposes the public half through the JWKS endpoint. The {@code kid} is a
 * stable UUID; clients pin to it and the discovery doc references it.
 *
 * The service is intentionally pure Java crypto + JPA — no Spring
 * Authorization Server. That keeps multi-tenancy clean: every operation
 * takes (or implicitly resolves) a tenant id and there is no shared
 * issuer-wide state to worry about.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class TenantSigningKeyService {

    public static final String RSA_ALG = "RS256";
    private static final int RSA_SIZE = 2048;

    private final TenantSigningKeyRepository repository;

    /**
     * Return the active key for the tenant, generating one on demand the
     * first time it's asked for. Idempotent under concurrent calls because
     * the {@link Transactional} method serialises through the DB unique
     * constraint on (tenant, active).
     */
    @Transactional
    public TenantSigningKey getOrCreateActive(Tenant tenant) {
        return repository.findFirstByTenantIdAndActiveTrue(tenant.getId())
                .orElseGet(() -> generate(tenant));
    }

    @Transactional
    public TenantSigningKey generate(Tenant tenant) {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(RSA_SIZE);
            KeyPair pair = gen.generateKeyPair();

            String kid = "wf-" + UUID.randomUUID();
            TenantSigningKey row = TenantSigningKey.builder()
                    .tenant(tenant)
                    .kid(kid)
                    .algorithm(RSA_ALG)
                    .publicKeyPem(toPem(pair.getPublic(), "PUBLIC KEY"))
                    .privateKeyPem(toPem(pair.getPrivate(), "PRIVATE KEY"))
                    .active(true)
                    .build();
            return repository.save(row);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate RSA keypair", e);
        }
    }

    /** Mark the current active key as rotated and mint a fresh one. */
    @Transactional
    public TenantSigningKey rotate(Tenant tenant) {
        repository.findFirstByTenantIdAndActiveTrue(tenant.getId()).ifPresent(old -> {
            old.setActive(false);
            old.setRotatedAt(LocalDateTime.now());
            repository.save(old);
        });
        return generate(tenant);
    }

    /** JWK Set: every key for the tenant, active and rotated alike. */
    public Map<String, Object> jwks(Tenant tenant) {
        List<TenantSigningKey> keys = repository.findByTenantId(tenant.getId());
        if (keys.isEmpty()) {
            // Lazily mint one so a brand-new tenant doesn't expose an empty JWKS.
            keys = List.of(getOrCreateActive(tenant));
        }
        return Map.of("keys", keys.stream().map(TenantSigningKeyService::toJwk).toList());
    }

    public RSAPublicKey loadPublicKey(TenantSigningKey row) {
        try {
            byte[] der = pemBody(row.getPublicKeyPem());
            return (RSAPublicKey) KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(der));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse stored public key for kid " + row.getKid(), e);
        }
    }

    public RSAPrivateKey loadPrivateKey(TenantSigningKey row) {
        try {
            byte[] der = pemBody(row.getPrivateKeyPem());
            return (RSAPrivateKey) KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse stored private key for kid " + row.getKid(), e);
        }
    }

    public TenantSigningKey requireByKid(String kid) {
        return repository.findByKid(kid)
                .orElseThrow(() -> new EntityNotFoundException("Unknown kid: " + kid));
    }

    // ---- Helpers ----------------------------------------------------

    static Map<String, Object> toJwk(TenantSigningKey row) {
        // Stand-alone JWK builder so we don't pull in nimbus-jose-jwt just
        // for this one shape.
        Map<String, Object> jwk = new LinkedHashMap<>();
        jwk.put("kty", "RSA");
        jwk.put("use", "sig");
        jwk.put("kid", row.getKid());
        jwk.put("alg", row.getAlgorithm());

        try {
            byte[] der = pemBody(row.getPublicKeyPem());
            RSAPublicKey pk = (RSAPublicKey) KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(der));
            jwk.put("n", base64UrlUnsigned(pk.getModulus().toByteArray()));
            jwk.put("e", base64UrlUnsigned(pk.getPublicExponent().toByteArray()));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to encode JWK for kid " + row.getKid(), e);
        }
        return jwk;
    }

    private static String toPem(java.security.Key key, String label) {
        String body = Base64.getEncoder().encodeToString(key.getEncoded());
        StringBuilder sb = new StringBuilder();
        sb.append("-----BEGIN ").append(label).append("-----\n");
        for (int i = 0; i < body.length(); i += 64) {
            sb.append(body, i, Math.min(i + 64, body.length())).append('\n');
        }
        sb.append("-----END ").append(label).append("-----\n");
        return sb.toString();
    }

    private static byte[] pemBody(String pem) {
        String body = pem.replaceAll("-----BEGIN [^-]+-----", "")
                .replaceAll("-----END [^-]+-----", "")
                .replaceAll("\\s", "");
        return Base64.getDecoder().decode(body);
    }

    /** Big-endian unsigned base64url, the form JWKs expect. */
    private static String base64UrlUnsigned(byte[] bytes) {
        // BigInteger encoding may have a leading 0x00 sign byte; strip it.
        int offset = (bytes.length > 1 && bytes[0] == 0) ? 1 : 0;
        byte[] trimmed = new byte[bytes.length - offset];
        System.arraycopy(bytes, offset, trimmed, 0, trimmed.length);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(trimmed);
    }

    // Suppress unused field warnings if a future caller stops using PublicKey/PrivateKey directly.
    @SuppressWarnings("unused")
    private static void typesUsed(PublicKey p, PrivateKey q) {}
}
