package io.aegis.policy;

/** Whose identity clients see for a hostname. */
public enum TlsMode {

    /** Aegis presents a copy of the origin's own certificate, so pinned clients keep working. */
    TRANSPARENT,

    /** Aegis presents its own certificate, as a classic reverse proxy does. */
    REVERSE_PROXY
}
