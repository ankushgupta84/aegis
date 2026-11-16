package io.aegis.policy;

import java.nio.file.Path;
import java.util.Optional;

/**
 * How Aegis connects to a route's backends and proves they are who they should be.
 *
 * <p>With TLS enabled the backend's certificate is always verified: against {@code pinnedSha256}
 * when set (for self-signed legacy origins), otherwise against {@code trustedCa} when set,
 * otherwise against the JVM's default trust store. There is no "trust anything" setting.
 *
 * @param trustedCa    a PEM file of CA certificates
 * @param pinnedSha256 the SHA-256 fingerprint of the backend's leaf certificate, as 64 hex digits
 */
public record UpstreamTls(boolean enabled, Optional<Path> trustedCa, Optional<String> pinnedSha256) {

    public static UpstreamTls plaintext() {
        return new UpstreamTls(false, Optional.empty(), Optional.empty());
    }
}
