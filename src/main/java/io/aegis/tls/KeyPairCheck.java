package io.aegis.tls;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

/**
 * Proves a private key belongs to a public key by signing a challenge and verifying it. This
 * works for any key type; comparing key parameters would need a code path per algorithm.
 */
final class KeyPairCheck {

    private static final byte[] CHALLENGE = "aegis key match".getBytes(StandardCharsets.US_ASCII);

    private KeyPairCheck() {
    }

    static boolean matches(PrivateKey key, PublicKey publicKey) throws GeneralSecurityException {
        var algorithm = signatureAlgorithm(publicKey.getAlgorithm());
        var signer = Signature.getInstance(algorithm);
        signer.initSign(key);
        signer.update(CHALLENGE);
        var signature = signer.sign();

        var verifier = Signature.getInstance(algorithm);
        verifier.initVerify(publicKey);
        verifier.update(CHALLENGE);
        return verifier.verify(signature);
    }

    /** @throws GeneralSecurityException for key types Aegis does not serve */
    static String signatureAlgorithm(String keyAlgorithm) throws GeneralSecurityException {
        return switch (keyAlgorithm) {
            case "RSA" -> "SHA256withRSA";
            case "EC" -> "SHA256withECDSA";
            default -> throw new GeneralSecurityException(
                    "unsupported key type " + keyAlgorithm + " (RSA and EC are supported)");
        };
    }
}
