package io.aegis.tls;

import io.aegis.policy.UpstreamTls;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HexFormat;
import javax.net.ssl.SSLException;

/**
 * Builds the client-side TLS contexts Aegis uses to reach backends. The backend certificate is
 * always verified: against a pinned fingerprint, a given CA bundle, or the JVM trust store.
 * Nothing here trusts an unverified peer.
 */
public final class UpstreamTlsContexts {

    private static final String HTTPS_ENDPOINT_IDENTIFICATION = "HTTPS";
    private static final int SHA256_HEX_LENGTH = 64;

    private UpstreamTlsContexts() {
    }

    /**
     * @throws IllegalArgumentException if TLS is not enabled, or the pin or the CA file is unusable
     */
    public static SslContext clientContext(UpstreamTls tls) {
        if (!tls.enabled()) {
            throw new IllegalArgumentException("upstream TLS is not enabled, so there is no client context to build");
        }
        var builder = SslContextBuilder.forClient()
                .sslProvider(SslProvider.JDK)
                .protocols("TLSv1.3", "TLSv1.2");
        if (tls.pinnedSha256().isPresent()) {
            builder.trustManager(new PinnedCertificateTrustManager(parsePin(tls.pinnedSha256().get())));
        } else {
            tls.trustedCa().ifPresent(ca -> builder.trustManager(readCaBundle(ca)));
            builder.endpointIdentificationAlgorithm(HTTPS_ENDPOINT_IDENTIFICATION);
        }
        try {
            return builder.build();
        } catch (SSLException e) {
            throw new IllegalArgumentException("cannot build the upstream TLS context: " + e.getMessage(), e);
        }
    }

    /** The SHA-256 of the certificate's DER encoding as 64 lowercase hex digits: the form used for pins. */
    public static String sha256Fingerprint(X509Certificate cert) {
        return HexFormat.of().formatHex(sha256Digest(cert));
    }

    static byte[] sha256Digest(X509Certificate cert) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(cert.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new IllegalArgumentException("the certificate cannot be DER-encoded: " + e.getMessage(), e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("every JVM provides SHA-256", e);
        }
    }

    private static byte[] parsePin(String pin) {
        if (pin.length() != SHA256_HEX_LENGTH) {
            throw invalidPin(pin, null);
        }
        try {
            return HexFormat.of().parseHex(pin);
        } catch (IllegalArgumentException e) {
            throw invalidPin(pin, e);
        }
    }

    private static IllegalArgumentException invalidPin(String pin, Throwable cause) {
        return new IllegalArgumentException(
                "pinned SHA-256 '" + pin + "' is not 64 hex digits (the SHA-256 of the certificate's DER encoding)", cause);
    }

    private static X509Certificate[] readCaBundle(Path caFile) {
        try {
            return PemReader.certificates(Files.readAllBytes(caFile)).toArray(new X509Certificate[0]);
        } catch (IOException | CertificateException e) {
            throw new IllegalArgumentException("trusted CA file " + caFile + " is not a readable PEM bundle of CA certificates: "
                    + e.getMessage(), e);
        }
    }
}
