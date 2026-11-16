package io.aegis.tls;

import java.net.Socket;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;

/**
 * Trusts exactly one server certificate, identified by the SHA-256 of its DER encoding.
 *
 * <p>The pin identifies the origin, so nothing else is checked: not the issuer, not the
 * validity dates, not the hostname. That is what makes self-signed legacy origins usable. It
 * extends {@link X509ExtendedTrustManager} so the JDK does not wrap it in a layer that adds
 * its own checks on top.
 */
final class PinnedCertificateTrustManager extends X509ExtendedTrustManager {

    private final byte[] pinnedDigest;

    /** @param pinnedDigest the SHA-256 digest of the one certificate to accept */
    PinnedCertificateTrustManager(byte[] pinnedDigest) {
        this.pinnedDigest = pinnedDigest.clone();
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
        checkServerTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
        checkServerTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        if (chain == null || chain.length == 0) {
            throw new CertificateException("the server sent no certificate");
        }
        var actual = UpstreamTlsContexts.sha256Digest(chain[0]);
        if (!MessageDigest.isEqual(pinnedDigest, actual)) {
            throw new CertificateException("the server certificate does not match the pinned fingerprint; it has sha256 "
                    + UpstreamTlsContexts.sha256Fingerprint(chain[0]));
        }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
        checkClientTrusted(chain, authType);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
        checkClientTrusted(chain, authType);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        throw new CertificateException("a pinned trust manager only verifies servers");
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}
