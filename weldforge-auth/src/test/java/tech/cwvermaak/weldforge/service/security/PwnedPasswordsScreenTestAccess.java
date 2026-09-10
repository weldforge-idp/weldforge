package tech.cwvermaak.weldforge.service.security;

import java.util.List;
import java.util.Set;

/**
 * Builds a real {@link PwnedPasswordsScreen} for tests outside this package,
 * with the network replaced by an in-memory corpus. The fake range endpoint
 * answers the way the real one does -- every suffix sharing the requested
 * prefix -- so the screen's own matching logic is what decides.
 */
public record PwnedPasswordsScreenTestAccess(Set<String> corpus, List<String> sentPrefixes) {

    public BreachedPasswordScreen screen() {
        return new PwnedPasswordsScreen("https://corpus.test/range/", prefix -> {
            sentPrefixes.add(prefix);
            StringBuilder body = new StringBuilder();
            for (String breached : corpus) {
                String hash = PwnedPasswordsScreen.sha1Hex(breached);
                if (hash.startsWith(prefix)) {
                    body.append(hash.substring(5)).append(":42\r\n");
                }
            }
            return body.toString();
        }, null);
    }
}
