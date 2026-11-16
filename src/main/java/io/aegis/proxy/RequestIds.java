package io.aegis.proxy;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Generates request IDs. The ID doubles as the incident ID shown to a blocked client, so it must
 * not be guessable: 96 random bits, URL-safe.
 */
final class RequestIds {

    private static final int BYTES = 12;
    private static final SecureRandom RANDOM = new SecureRandom();

    private RequestIds() {
    }

    static String next() {
        byte[] bytes = new byte[BYTES];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
