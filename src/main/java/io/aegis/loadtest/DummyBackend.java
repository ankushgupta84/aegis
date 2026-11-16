package io.aegis.loadtest;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.HttpServerExpectContinueHandler;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import java.net.InetSocketAddress;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLException;

/**
 * The origin server of a benchmark: it answers every request {@code 200} with its own name, so
 * the load generator can measure a proxy against a backend whose own cost is known and tiny.
 * Run it directly for the "direct" half of a direct-versus-through-Aegis comparison, or start it
 * in-process from a test.
 */
public final class DummyBackend {

    private static final int IO_THREADS = 2;

    private DummyBackend() {
    }

    /** A running backend; closing it releases the port and the threads. */
    public static final class Handle implements AutoCloseable {

        private final EventLoopGroup group;
        private final Channel server;

        private Handle(EventLoopGroup group, Channel server) {
            this.group = group;
            this.server = server;
        }

        public int port() {
            return ((InetSocketAddress) server.localAddress()).getPort();
        }

        @Override
        public void close() {
            server.close().syncUninterruptibly();
            group.shutdownGracefully(0, 1, TimeUnit.SECONDS).syncUninterruptibly();
        }
    }

    public static Handle start(BackendOptions options) throws SSLException {
        SslContext ssl = options.tls().isEmpty()
                ? null
                : SslContextBuilder.forServer(
                                options.tls().get().certificate().toFile(),
                                options.tls().get().key().toFile())
                        .build();
        Transport transport = Transport.best();
        EventLoopGroup group = transport.newGroup(IO_THREADS);
        long delayNanos = options.delay().toNanos();
        try {
            Channel server = new ServerBootstrap()
                    .group(group)
                    .channel(transport.serverChannel())
                    .childHandler(new ChannelInitializer<Channel>() {
                        @Override
                        protected void initChannel(Channel channel) {
                            if (ssl != null) {
                                channel.pipeline().addLast(ssl.newHandler(channel.alloc()));
                            }
                            channel.pipeline()
                                    .addLast(new HttpServerCodec())
                                    .addLast(new HttpServerExpectContinueHandler())
                                    .addLast(new BackendHandler(options.name(), delayNanos));
                        }
                    })
                    .bind(options.port())
                    .syncUninterruptibly()
                    .channel();
            return new Handle(group, server);
        } catch (RuntimeException e) {
            group.shutdownGracefully(0, 1, TimeUnit.SECONDS);
            throw e;
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 1 && args[0].equals("--help")) {
            System.out.print(BackendOptions.HELP);
            return;
        }
        BackendOptions options;
        try {
            options = BackendOptions.parse(args);
        } catch (UsageException e) {
            System.err.println("error: " + e.getMessage() + "\n\n" + BackendOptions.HELP);
            System.exit(2);
            return;
        }
        Handle backend = start(options);
        System.out.println("backend " + options.name() + " listening on port " + backend.port()
                + (options.tls().isPresent() ? " (TLS)" : ""));
        Thread.currentThread().join();
    }
}
