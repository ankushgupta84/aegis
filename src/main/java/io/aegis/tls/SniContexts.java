package io.aegis.tls;

import io.netty.handler.ssl.SslContext;
import io.netty.util.Mapping;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Chooses the {@link SslContext} for a requested server name: exact match first, then a
 * single-label wildcard.
 *
 * <p>There is deliberately no default. A name without a match throws, which makes Netty's
 * {@code SniHandler} fail the connection instead of presenting some other host's certificate.
 */
final class SniContexts implements Mapping<String, SslContext> {

    /** Thrown for a missing or unmatched server name. */
    static final class UnknownServerNameException extends RuntimeException {
        UnknownServerNameException(String message) {
            super(message);
        }
    }

    /** Configured hostname or {@code *.suffix} pattern, lowercase, to the context currently served. */
    private final Map<String, AtomicReference<SslContext>> byPattern;

    SniContexts(Map<String, AtomicReference<SslContext>> byPattern) {
        this.byPattern = Map.copyOf(byPattern);
    }

    @Override
    public SslContext map(String serverName) {
        if (serverName == null) {
            throw new UnknownServerNameException("the client sent no server name (SNI)");
        }
        var name = serverName.toLowerCase(Locale.ROOT);
        var holder = byPattern.get(name);
        if (holder == null) {
            holder = byPattern.get(wildcardFor(name));
        }
        if (holder == null) {
            throw new UnknownServerNameException("no certificate is configured for " + name);
        }
        return holder.get();
    }

    /** {@code a.example.com} becomes {@code *.example.com}; a name without a parent label has none. */
    private static String wildcardFor(String name) {
        int firstDot = name.indexOf('.');
        return firstDot > 0 ? "*" + name.substring(firstDot) : "";
    }
}
