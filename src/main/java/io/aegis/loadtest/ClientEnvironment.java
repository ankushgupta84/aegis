package io.aegis.loadtest;

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.handler.codec.http.HttpClientCodec;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslHandler;
import java.util.Arrays;
import java.util.List;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;

/** How to reach the target: transport, address, and the TLS settings that verify its certificate. */
final class ClientEnvironment {

    private final Bootstrap bootstrap;
    private final SslContext ssl;
    private final String host;
    private final int port;
    private final String hostHeader;
    private final byte[] bodyFiller;

    private ClientEnvironment(Bootstrap bootstrap, SslContext ssl, LoadTestOptions options) {
        this.bootstrap = bootstrap;
        this.ssl = ssl;
        this.host = options.url().getHost();
        this.port = options.port();
        this.hostHeader = options.hostHeader();
        this.bodyFiller = new byte[options.bodyMaxBytes()];
        // Benign text, so the body itself never trips a WAF rule.
        Arrays.fill(bodyFiller, (byte) 'a');
    }

    static ClientEnvironment create(LoadTestOptions options, Transport transport, EventLoopGroup group)
            throws SSLException {
        SslContext ssl = options.https() ? clientContext(options) : null;
        Bootstrap bootstrap = new Bootstrap()
                .group(group)
                .channel(transport.clientChannel())
                .option(ChannelOption.TCP_NODELAY, true)
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, (int) Math.min(Integer.MAX_VALUE, options.timeout().toMillis()))
                .remoteAddress(options.url().getHost(), options.port());
        return new ClientEnvironment(bootstrap, ssl, options);
    }

    String hostHeader() {
        return hostHeader;
    }

    /** Read-only bytes that every POST body is cut from. */
    byte[] bodyFiller() {
        return bodyFiller;
    }

    /** Opens a connection whose responses go to {@code handler}. */
    ChannelFuture connect(ResponseHandler handler) {
        return bootstrap.clone().handler(new ChannelInitializer<Channel>() {
            @Override
            protected void initChannel(Channel channel) {
                if (ssl != null) {
                    channel.pipeline().addLast(verifyingHandler(channel));
                }
                channel.pipeline().addLast(new HttpClientCodec()).addLast(handler);
            }
        }).connect();
    }

    private SslHandler verifyingHandler(Channel channel) {
        SslHandler handler = ssl.newHandler(channel.alloc(), host, port);
        SSLEngine engine = handler.engine();
        SSLParameters parameters = engine.getSSLParameters();
        // Netty checks the certificate chain but not that it names the host unless asked.
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        if (isHostName(host)) {
            // The JDK sends no server name for a name without a dot, such as "localhost", and a
            // server that picks its certificate by name then refuses the handshake.
            parameters.setServerNames(List.of(new SNIHostName(host)));
        }
        engine.setSSLParameters(parameters);
        return handler;
    }

    /** An IP literal is not a server name and must not be sent as one. */
    private static boolean isHostName(String host) {
        return !host.contains(":") && !host.matches("[0-9.]+");
    }

    private static SslContext clientContext(LoadTestOptions options) throws SSLException {
        SslContextBuilder builder = SslContextBuilder.forClient();
        options.tlsTrust().ifPresent(pem -> builder.trustManager(pem.toFile()));
        return builder.build();
    }
}
