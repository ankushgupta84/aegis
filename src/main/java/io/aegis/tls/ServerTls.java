package io.aegis.tls;

import io.aegis.plugin.CertificateProvider;
import io.aegis.plugin.CertificateProvider.Material;
import io.aegis.plugin.CertificateProviderFactory;
import io.aegis.plugin.CertificateUnavailableException;
import io.aegis.policy.TlsHost;
import io.netty.handler.ssl.SslContext;
import io.netty.util.Mapping;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import javax.net.ssl.SSLException;

/**
 * The server certificates of a listener: one per configured hostname, each kept current by its
 * certificate provider.
 *
 * <p>When a provider reports new material, the hostname's context is replaced atomically. New
 * handshakes use the new certificate; established connections are untouched.
 *
 * <p>There is deliberately no default certificate. The mapping from {@link #contextsBySni()}
 * throws for a missing or unknown server name; Netty's {@code SniHandler} then fails the
 * connection (see {@code ServerTlsHandshakeTest}), so the client never sees another host's
 * certificate. The pipeline must close the channel on that exception, as it does for any other.
 *
 * <p>Events are delivered from the providers' polling threads, so the consumer must be thread-safe
 * and must not throw.
 */
public final class ServerTls implements AutoCloseable {

    private final SniContexts contexts;
    private final List<CertificateProvider> providers;

    private ServerTls(SniContexts contexts, List<CertificateProvider> providers) {
        this.contexts = contexts;
        this.providers = providers;
    }

    /**
     * Loads every host's certificate and starts watching for changes.
     *
     * @throws CertificateUnavailableException if any host's certificate cannot be loaded; nothing stays open
     * @throws IllegalArgumentException        for an unknown provider type, a bad hostname or a duplicate
     */
    public static ServerTls open(List<TlsHost> hosts, Consumer<CertificateEvent> events) {
        return open(hosts, factoriesByType(), events);
    }

    /** Separate from the public method so tests can supply the factories and drive reloads themselves. */
    static ServerTls open(List<TlsHost> hosts, Map<String, CertificateProviderFactory> factories,
                          Consumer<CertificateEvent> events) {
        var holders = new HashMap<String, AtomicReference<SslContext>>();
        var providers = new ArrayList<CertificateProvider>();
        var pending = new ArrayList<Runnable>();
        try {
            for (var host : hosts) {
                var pattern = validatedPattern(host.hostname(), holders);
                var provider = create(factories, host);
                providers.add(provider);
                var holder = new AtomicReference<>(initialContext(pattern, provider, events));
                holders.put(pattern, holder);
                pending.add(() -> provider.watch(
                        material -> reload(pattern, holder, material, events),
                        failure -> events.accept(new CertificateEvent(
                                pattern, CertificateEvent.Kind.RELOAD_FAILED, failure.getMessage()))));
            }
        } catch (RuntimeException e) {
            closeAll(providers, e);
            throw e;
        }
        pending.forEach(Runnable::run);
        return new ServerTls(new SniContexts(holders), providers);
    }

    /** The mapping for Netty's {@code SniHandler}. */
    public Mapping<String, SslContext> contextsBySni() {
        return contexts;
    }

    @Override
    public void close() {
        closeAll(providers, null);
    }

    private static SslContext initialContext(String pattern, CertificateProvider provider,
                                             Consumer<CertificateEvent> events) {
        try {
            var material = provider.load();
            var context = ServerContexts.create(material);
            events.accept(new CertificateEvent(pattern, CertificateEvent.Kind.LOADED, describe(material)));
            return context;
        } catch (CertificateUnavailableException e) {
            throw new CertificateUnavailableException("TLS host " + pattern + ": " + e.getMessage(), e);
        } catch (SSLException e) {
            throw new CertificateUnavailableException(
                    "TLS host " + pattern + ": the certificate cannot be used for TLS: " + e.getMessage(), e);
        }
    }

    private static void reload(String pattern, AtomicReference<SslContext> holder, Material material,
                               Consumer<CertificateEvent> events) {
        try {
            holder.set(ServerContexts.create(material));
            events.accept(new CertificateEvent(pattern, CertificateEvent.Kind.RELOADED, describe(material)));
        } catch (SSLException e) {
            events.accept(new CertificateEvent(pattern, CertificateEvent.Kind.RELOAD_FAILED,
                    "the new certificate cannot be used for TLS: " + e.getMessage()));
        }
    }

    private static String describe(Material material) {
        var leaf = material.chain().get(0);
        return "sha256=" + UpstreamTlsContexts.sha256Fingerprint(leaf)
                + " notAfter=" + leaf.getNotAfter().toInstant();
    }

    private static String validatedPattern(String hostname, Map<String, ?> configured) {
        var pattern = hostname.toLowerCase(Locale.ROOT);
        var wildcardOk = pattern.startsWith("*.") && pattern.indexOf('*', 1) < 0 && pattern.length() > 2;
        if (pattern.isEmpty() || (pattern.contains("*") && !wildcardOk)) {
            throw new IllegalArgumentException("'" + hostname
                    + "' is not a valid TLS hostname; use a name or a single leading wildcard such as *.example.com");
        }
        if (configured.containsKey(pattern)) {
            throw new IllegalArgumentException("TLS hostname " + pattern + " is configured twice");
        }
        return pattern;
    }

    private static CertificateProvider create(Map<String, CertificateProviderFactory> factories, TlsHost host) {
        var factory = factories.get(host.providerType());
        if (factory == null) {
            throw new IllegalArgumentException("TLS host " + host.hostname() + " uses unknown certificate provider type '"
                    + host.providerType() + "'; available types: " + new TreeSet<>(factories.keySet()));
        }
        try {
            return factory.create(host.providerSettings());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("TLS host " + host.hostname() + ": " + e.getMessage(), e);
        }
    }

    private static Map<String, CertificateProviderFactory> factoriesByType() {
        var factories = new HashMap<String, CertificateProviderFactory>();
        for (var factory : ServiceLoader.load(CertificateProviderFactory.class)) {
            if (factories.putIfAbsent(factory.type(), factory) != null) {
                throw new IllegalStateException("two certificate provider factories claim the type " + factory.type());
            }
        }
        return factories;
    }

    private static void closeAll(List<CertificateProvider> providers, RuntimeException primary) {
        RuntimeException failure = primary;
        for (var provider : providers) {
            try {
                provider.close();
            } catch (RuntimeException e) {
                if (failure == null) {
                    failure = e;
                } else if (failure != e) {
                    failure.addSuppressed(e);
                }
            }
        }
        if (failure != null && failure != primary) {
            throw failure;
        }
    }
}
