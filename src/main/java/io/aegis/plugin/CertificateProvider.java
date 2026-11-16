package io.aegis.plugin;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.function.Consumer;

/**
 * A source of the certificate Aegis presents for one hostname. Implementations cover a cloud
 * certificate manager, an ACME CA, or files on disk.
 *
 * <p>A provider is part of the system, not a guest in it: a failure to load is thrown, never
 * swallowed, and the caller logs and counts it.
 */
public interface CertificateProvider extends AutoCloseable {

    /** The certificate chain (leaf first) and its private key. */
    record Material(List<X509Certificate> chain, PrivateKey key) {
        public Material {
            chain = List.copyOf(chain);
        }
    }

    /**
     * Loads the current certificate.
     *
     * @throws CertificateUnavailableException when nothing usable can be loaded
     */
    Material load();

    /**
     * Calls {@code listener} with new material each time the certificate changes. A change that
     * cannot be loaded is reported to {@code onFailure} and the previous material stays in use.
     */
    void watch(Consumer<Material> listener, Consumer<CertificateUnavailableException> onFailure);

    @Override
    void close();
}
