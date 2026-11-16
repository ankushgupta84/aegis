package io.aegis.plugin;

/** A certificate provider could not produce a usable certificate and key. */
public class CertificateUnavailableException extends RuntimeException {

    public CertificateUnavailableException(String message) {
        super(message);
    }

    public CertificateUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
