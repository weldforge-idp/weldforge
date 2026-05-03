package tech.cwvermaak.weldforge.service.mfa;

import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.exception.Base64UrlException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import tech.cwvermaak.weldforge.model.MfaFactor;
import tech.cwvermaak.weldforge.model.MfaFactorType;
import tech.cwvermaak.weldforge.model.User;
import tech.cwvermaak.weldforge.repository.MfaFactorRepository;
import tech.cwvermaak.weldforge.repository.UserRepository;

import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Adapter between the Yubico WebAuthn library and our own DB. The Yubico
 * {@link CredentialRepository} contract talks in terms of "username" and
 * "user handle"; we use the user's email as the username and the user's
 * numeric id (8 bytes, big-endian) as the handle — both are globally unique
 * because email is tenant-scoped and ids are DB-assigned.
 *
 * Tenant isolation is preserved because credentials are bound to a specific
 * user row, and the user row owns a tenant. Cross-tenant credential lookup
 * is not possible: {@link #lookup(ByteArray, ByteArray)} requires both the
 * credentialId and the user handle to match.
 */
@Component
@RequiredArgsConstructor
public class WebAuthnCredentialRepository implements CredentialRepository {

    private final MfaFactorRepository mfaFactorRepository;
    private final UserRepository userRepository;

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        return userRepository.findFirstByEmailIgnoreCase(username)
                .map(u -> mfaFactorRepository.findByUserIdAndType(u.getId(), MfaFactorType.WEBAUTHN).stream()
                        .filter(f -> Boolean.TRUE.equals(f.getEnabled())
                                  && Boolean.TRUE.equals(f.getVerified()))
                        .map(f -> PublicKeyCredentialDescriptor.builder()
                                .id(decode(f.getCredentialId()))
                                .build())
                        .collect(Collectors.toSet()))
                .orElseGet(Set::of);
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {
        return userRepository.findFirstByEmailIgnoreCase(username)
                .map(u -> userHandle(u.getId()));
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        Long id = fromUserHandle(userHandle);
        if (id == null) return Optional.empty();
        return userRepository.findById(id).map(User::getEmail);
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        Long uid = fromUserHandle(userHandle);
        return mfaFactorRepository.findByCredentialId(credentialId.getBase64Url())
                .filter(f -> f.getUser() != null && uid != null && uid.equals(f.getUser().getId()))
                .map(WebAuthnCredentialRepository::toRegisteredCredential);
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        return mfaFactorRepository.findByCredentialId(credentialId.getBase64Url())
                .map(WebAuthnCredentialRepository::toRegisteredCredential)
                .map(Set::of)
                .orElseGet(Set::of);
    }

    // -- helpers --------------------------------------------------------

    public static ByteArray userHandle(Long userId) {
        byte[] buf = new byte[8];
        long v = userId;
        for (int i = 7; i >= 0; i--) {
            buf[i] = (byte) (v & 0xff);
            v >>>= 8;
        }
        return new ByteArray(buf);
    }

    public static Long fromUserHandle(ByteArray handle) {
        if (handle == null) return null;
        byte[] buf = handle.getBytes();
        if (buf.length != 8) return null;
        long v = 0;
        for (byte b : buf) v = (v << 8) | (b & 0xff);
        return v;
    }

    private static RegisteredCredential toRegisteredCredential(MfaFactor f) {
        return RegisteredCredential.builder()
                .credentialId(decode(f.getCredentialId()))
                .userHandle(userHandle(f.getUser().getId()))
                .publicKeyCose(decode(f.getPublicKeyCose()))
                .signatureCount(f.getSignatureCount() == null ? 0 : f.getSignatureCount())
                .build();
    }

    private static ByteArray decode(String base64url) {
        try {
            return ByteArray.fromBase64Url(base64url);
        } catch (Base64UrlException e) {
            throw new IllegalStateException("Corrupt base64url in stored credential: " + e.getMessage(), e);
        }
    }
}
