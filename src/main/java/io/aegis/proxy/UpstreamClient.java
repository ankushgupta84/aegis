package io.aegis.proxy;

import io.aegis.policy.BackendAddress;
import io.aegis.policy.UpstreamPolicy;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoop;
import io.netty.handler.codec.http.HttpClientCodec;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslHandler;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.Promise;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Connections from one route to its backends. Each event loop keeps its own idle connections and
 * every connection lives on the loop of the client that uses it, so a request never crosses
 * threads and the pool needs no locks.
 *
 * <p>Backend host names are resolved once, when the route is built: resolving on the event loop
 * would block it. The cost is that a changed DNS record is not noticed until restart.
 */
final class UpstreamClient {

    private static final int MAX_RESPONSE_LINE_BYTES = 4096;
    private static final int MAX_RESPONSE_HEADER_BYTES = 16 * 1024;
    private static final int MAX_CHUNK_BYTES = 64 * 1024;

    private final Transport transport;
    private final Optional<SslContext> tls;
    private final int connectTimeoutMillis;
    private final Map<BackendAddress, InetSocketAddress> addresses = new HashMap<>();
    private final Map<EventLoop, IdleConnections> pools = new ConcurrentHashMap<>();

    UpstreamClient(Transport transport, UpstreamPolicy policy, Optional<SslContext> tls) {
        this.transport = transport;
        this.tls = tls;
        this.connectTimeoutMillis = Math.toIntExact(policy.connectTimeout().toMillis());
        for (BackendAddress backend : policy.backends()) {
            addresses.put(backend, resolve(backend));
        }
    }

    private static InetSocketAddress resolve(BackendAddress backend) {
        try {
            return new InetSocketAddress(InetAddress.getByName(backend.host()), backend.port());
        } catch (UnknownHostException e) {
            throw new StartupException("Cannot resolve backend host '" + backend.host() + "'", e);
        }
    }

    /**
     * Gets a connection on {@code loop}: an idle one if allowed and any is live, otherwise a new
     * one, which for TLS backends is returned only after the handshake succeeded.
     */
    Future<UpstreamConnection> acquire(EventLoop loop, BackendAddress backend, boolean allowIdle) {
        IdleConnections pool = pools.computeIfAbsent(loop, l -> new IdleConnections());
        Promise<UpstreamConnection> promise = loop.newPromise();
        UpstreamConnection idle = allowIdle ? pool.take(backend) : null;
        if (idle != null) {
            promise.setSuccess(idle);
        } else {
            connect(loop, pool, backend, promise);
        }
        return promise;
    }

    private void connect(EventLoop loop, IdleConnections pool, BackendAddress backend,
            Promise<UpstreamConnection> promise) {
        UpstreamConnection connection = new UpstreamConnection(pool, backend);
        new Bootstrap()
                .group(loop)
                .channel(transport.clientChannel())
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, connectTimeoutMillis)
                .option(ChannelOption.TCP_NODELAY, true)
                .handler(new ChannelInitializer<Channel>() {
                    @Override
                    protected void initChannel(Channel channel) {
                        tls.ifPresent(context -> channel.pipeline().addLast(sslHandler(context, channel, backend)));
                        channel.pipeline().addLast(
                                new HttpClientCodec(MAX_RESPONSE_LINE_BYTES, MAX_RESPONSE_HEADER_BYTES, MAX_CHUNK_BYTES),
                                connection);
                    }
                })
                .connect(addresses.get(backend))
                .addListener((ChannelFuture connected) -> {
                    if (!connected.isSuccess()) {
                        promise.tryFailure(connected.cause());
                        return;
                    }
                    Channel channel = connected.channel();
                    SslHandler ssl = channel.pipeline().get(SslHandler.class);
                    if (ssl == null) {
                        promise.trySuccess(connection);
                        return;
                    }
                    ssl.handshakeFuture().addListener(handshake -> {
                        if (handshake.isSuccess()) {
                            promise.trySuccess(connection);
                        } else {
                            channel.close();
                            promise.tryFailure(handshake.cause());
                        }
                    });
                });
    }

    /** SNI and hostname verification use the configured backend host, never the resolved address. */
    private SslHandler sslHandler(SslContext context, Channel channel, BackendAddress backend) {
        SslHandler handler = context.newHandler(channel.alloc(), backend.host(), backend.port());
        handler.setHandshakeTimeoutMillis(connectTimeoutMillis);
        return handler;
    }
}
