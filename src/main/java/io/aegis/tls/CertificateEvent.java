package io.aegis.tls;

/**
 * Something that happened to the certificate of one hostname, reported so the caller can log and
 * count it.
 *
 * @param hostname the configured hostname or wildcard pattern
 * @param detail   what the operator needs to see: the certificate's fingerprint and expiry, or the reason for a failure
 */
public record CertificateEvent(String hostname, Kind kind, String detail) {

    public enum Kind {
        /** The first certificate loaded at startup. */
        LOADED,
        /** A changed certificate is now served to new handshakes. */
        RELOADED,
        /** A change could not be loaded; the previous certificate is still served. */
        RELOAD_FAILED
    }
}
