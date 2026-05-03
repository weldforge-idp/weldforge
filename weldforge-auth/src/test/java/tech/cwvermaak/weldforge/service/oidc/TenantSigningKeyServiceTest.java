package tech.cwvermaak.weldforge.service.oidc;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import tech.cwvermaak.weldforge.model.Tenant;
import tech.cwvermaak.weldforge.model.TenantSigningKey;
import tech.cwvermaak.weldforge.repository.TenantSigningKeyRepository;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class TenantSigningKeyServiceTest {

    private TenantSigningKeyRepository repo;
    private TenantSigningKeyService service;
    private Tenant tenant;
    private List<TenantSigningKey> store;

    @BeforeEach
    void setUp() {
        repo = mock(TenantSigningKeyRepository.class);
        service = new TenantSigningKeyService(repo);
        tenant = Tenant.builder().id(1L).slug("acme").name("Acme").build();
        store = new ArrayList<>();

        AtomicLong idSeq = new AtomicLong(1);
        when(repo.save(any(TenantSigningKey.class))).thenAnswer(inv -> {
            TenantSigningKey k = inv.getArgument(0);
            if (k.getId() == null) {
                k.setId(idSeq.getAndIncrement());
                // Simulate the @PrePersist hook so subsequent reads see createdAt set.
                if (k.getCreatedAt() == null) k.setCreatedAt(java.time.LocalDateTime.now());
                store.add(k);
            }
            // Idempotent upsert: rows with an id are already in `store`,
            // their fields have been mutated in place by the caller.
            return k;
        });
        when(repo.findFirstByTenantIdAndActiveTrue(1L)).thenAnswer(inv ->
                store.stream().filter(k -> Boolean.TRUE.equals(k.getActive())).findFirst());
        when(repo.findByTenantId(1L)).thenAnswer(inv -> List.copyOf(store));
    }

    @Test
    @DisplayName("getOrCreateActive mints a fresh RSA-2048 key on first call and reuses it after")
    void firstCall_mintsKey_subsequentReuses() {
        TenantSigningKey first = service.getOrCreateActive(tenant);
        TenantSigningKey second = service.getOrCreateActive(tenant);

        assertThat(first.getKid()).isNotBlank();
        assertThat(first.getAlgorithm()).isEqualTo("RS256");
        assertThat(first.getPublicKeyPem()).contains("BEGIN PUBLIC KEY");
        assertThat(first.getPrivateKeyPem()).contains("BEGIN PRIVATE KEY");
        assertThat(second).isSameAs(first);

        // Sanity check: the key actually round-trips through KeyFactory.
        RSAPublicKey pub = service.loadPublicKey(first);
        RSAPrivateKey priv = service.loadPrivateKey(first);
        assertThat(pub.getModulus().bitLength()).isGreaterThanOrEqualTo(2048);
        assertThat(priv.getModulus()).isEqualTo(pub.getModulus());
    }

    @Test
    @DisplayName("rotate marks the old key inactive and mints a fresh active one")
    void rotate_mintsNewKeepsOld() {
        TenantSigningKey first = service.getOrCreateActive(tenant);
        TenantSigningKey rotated = service.rotate(tenant);

        assertThat(rotated.getId()).isNotEqualTo(first.getId());
        assertThat(rotated.getKid()).isNotEqualTo(first.getKid());
        assertThat(first.getActive()).isFalse();
        assertThat(first.getRotatedAt()).isNotNull();
        assertThat(rotated.getActive()).isTrue();
    }

    @Test
    @DisplayName("jwks returns one entry per stored key with the correct fields")
    void jwks_publishesAllKeys() {
        service.getOrCreateActive(tenant);
        service.rotate(tenant);

        Map<String, Object> jwks = service.jwks(tenant);
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> keys = (List<Map<String, Object>>) jwks.get("keys");
        assertThat(keys).hasSize(2);
        for (Map<String, Object> jwk : keys) {
            assertThat(jwk).containsEntry("kty", "RSA");
            assertThat(jwk).containsEntry("use", "sig");
            assertThat(jwk).containsEntry("alg", "RS256");
            assertThat(jwk).containsKey("kid");
            assertThat(jwk).containsKey("n");
            assertThat(jwk).containsKey("e");
        }
    }

    @Test
    @DisplayName("requireByKid resolves a stored key")
    void requireByKid_lookup() {
        TenantSigningKey key = service.getOrCreateActive(tenant);
        when(repo.findByKid(key.getKid())).thenReturn(Optional.of(key));

        assertThat(service.requireByKid(key.getKid())).isSameAs(key);
    }
}
