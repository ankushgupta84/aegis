package io.aegis.tls;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.List;

/**
 * Parses PEM text with the JDK alone. Parsing is strict and explicit about what is not
 * supported (encrypted or PKCS#1 keys), so an operator learns the fix from the error message.
 */
final class PemReader {

    private static final String PKCS8_BEGIN = "-----BEGIN PRIVATE KEY-----";
    private static final String PKCS8_END = "-----END PRIVATE KEY-----";

    private PemReader() {
    }

    /** @throws CertificateException when the text holds no certificate or is malformed */
    static List<X509Certificate> certificates(byte[] pem) throws CertificateException {
        var parsed = CertificateFactory.getInstance("X.509").generateCertificates(new ByteArrayInputStream(pem));
        if (parsed.isEmpty()) {
            throw new CertificateException("no PEM certificate found");
        }
        return parsed.stream().map(X509Certificate.class::cast).toList();
    }

    /**
     * @param algorithm the key algorithm, taken from the matching certificate (RSA or EC)
     * @throws GeneralSecurityException when the text is not an unencrypted PKCS#8 key of that algorithm
     */
    static PrivateKey pkcs8PrivateKey(byte[] pem, String algorithm) throws GeneralSecurityException {
        var text = new String(pem, StandardCharsets.US_ASCII);
        if (text.contains("BEGIN ENCRYPTED PRIVATE KEY")) {
            throw new GeneralSecurityException("the key is encrypted; provide an unencrypted PKCS#8 key");
        }
        int begin = text.indexOf(PKCS8_BEGIN);
        int end = text.indexOf(PKCS8_END);
        if (begin < 0 || end < begin) {
            throw new GeneralSecurityException("no PKCS#8 'BEGIN PRIVATE KEY' block found"
                    + " (convert with: openssl pkcs8 -topk8 -nocrypt)");
        }
        var base64 = text.substring(begin + PKCS8_BEGIN.length(), end).replaceAll("\\s", "");
        try {
            var der = Base64.getDecoder().decode(base64);
            return KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (IllegalArgumentException e) {
            throw new GeneralSecurityException("the key block is not valid base64", e);
        }
    }
}
