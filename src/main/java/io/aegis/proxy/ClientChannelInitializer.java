package io.aegis.proxy;

import io.aegis.policy.Listener;
import io.aegis.tls.ServerTls;
import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.handler.codec.http.HttpDecoderConfig;
import io.netty.handler.codec.http.HttpResponseEncoder;
import io.netty.handler.ssl.SniHandler;
import io.netty.handler.timeout.IdleStateHandler;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * Builds the pipeline of every client connection:
 * {@code [SNI/TLS] idle-timeout → request decoder (header timeout) → response encoder →
 * body-limiting aggregator → request handler}.
 */
final class ClientChannelInitializer extends ChannelInitializer<Channel> {

    private static final int MAX_REQUEST_LINE_BYTES = 8192;

    private final Listener listener;
    private final Optional<ServerTls> serverTls;
    private final Screening screening;
    private final Telemetry telemetry;
    private final Drain drain;

    ClientChannelInitializer(Listener listener, Optional<ServerTls> serverTls, Screening screening,
            Telemetry telemetry, Drain drain) {
        this.listener = listener;
        this.serverTls = serverTls;
        this.screening = screening;
        this.telemetry = telemetry;
        this.drain = drain;
    }

    @Override
    protected void initChannel(Channel channel) {
        ChannelPipeline pipeline = channel.pipeline();
        serverTls.ifPresent(tls -> pipeline.addLast(new SniHandler(tls.contextsBySni())));
        HttpDecoderConfig decoder = new HttpDecoderConfig()
                .setMaxInitialLineLength(Math.min(MAX_REQUEST_LINE_BYTES, listener.maxHeaderBytes()))
                .setMaxHeaderSize(listener.maxHeaderBytes());
        pipeline.addLast(
                new IdleStateHandler(0, 0, listener.idleTimeout().toMillis(), TimeUnit.MILLISECONDS),
                new RequestDecoder(decoder, listener.headerTimeout()),
                new HttpResponseEncoder(),
                new BodyLimitAggregator(listener.maxBodyBytes()),
                new RequestHandler(screening, telemetry, drain, listener.tls()));
    }
}
