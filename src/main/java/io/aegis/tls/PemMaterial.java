package io.aegis.tls;

import io.aegis.plugin.CertificateProvider.Material;
import io.aegis.plugin.CertificateUnavailableException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Turns the bytes of a certificate file and a key file into validated {@link Material}. Every
 * failure names the file at fault, because an operator reads it in a log line.
 */
final class PemMaterial {

    private PemMaterial() {
    }

    static Material parse(Path certFile, byte[] certPem, Path keyFile, byte[] keyPem) {
        var chain = parseChain(certFile, certPem);
        var leaf = chain.get(0);
        try {
            var publicKey = leaf.getPublicKey();
            var key = PemReader.pkcs8PrivateKey(keyPem, publicKey.getAlgorithm());
            if (!KeyPairCheck.matches(key, publicKey)) {
                throw new CertificateUnavailableException(
                        "key_file " + keyFile + " does not match the certificate in cert_file " + certFile);
            }
            return new Material(chain, key);
        } catch (GeneralSecurityException e) {
            throw new CertificateUnavailableException("key_file " + keyFile + " is unusable: " + e.getMessage(), e);
        }
    }

    private static List<X509Certificate> parseChain(Path certFile, byte[] certPem) {
        try {
            return PemReader.certificates(certPem);
        } catch (CertificateException e) {
            throw new CertificateUnavailableException(
                    "cert_file " + certFile + " is not a PEM certificate chain: " + e.getMessage(), e);
        }
    }
}
