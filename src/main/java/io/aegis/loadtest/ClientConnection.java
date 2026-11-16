package io.aegis.loadtest;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.handler.codec.http.DefaultFullHttpRequest;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpUtil;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.ssl.SslHandler;

/**
 * One client connection that carries one request at a time (no pipelining). It connects on first
 * use and reconnects after the channel dies, so connect and TLS handshake time lands inside the
 * latency of the request that needed them. Used only from the dispatcher's thread.
 */
final class ClientConnection {

    private final ClientEnvironment environment;
    private Channel channel;
    private ResponseHandler handler;

    ClientConnection(ClientEnvironment environment) {
        this.environment = environment;
    }

    void execute(RequestSpec spec, ExchangeListener listener) {
        if (channel != null && channel.isActive()) {
            send(channel, handler, spec, listener);
            return;
        }
        ResponseHandler freshHandler = new ResponseHandler();
        ChannelFuture connecting = environment.connect(freshHandler);
        channel = connecting.channel();
        handler = freshHandler;
        connecting.addListener((ChannelFutureListener) connected -> {
            if (!connected.isSuccess()) {
                listener.failed(ErrorCause.CONNECT_FAILURE);
                return;
            }
            sendWhenSecure(connected.channel(), freshHandler, spec, listener);
        });
    }

    /** Drops the channel, e.g. after a timeout, when its state is unknown. */
    void close() {
        if (channel != null) {
            channel.close();
            channel = null;
        }
    }

    private void sendWhenSecure(Channel ch, ResponseHandler responses, RequestSpec spec, ExchangeListener listener) {
        SslHandler ssl = ch.pipeline().get(SslHandler.class);
        if (ssl == null) {
            send(ch, responses, spec, listener);
            return;
        }
        ssl.handshakeFuture().addListener(handshake -> {
            if (handshake.isSuccess()) {
                send(ch, responses, spec, listener);
            } else {
                ch.close();
                listener.failed(ErrorCause.TLS_FAILURE);
            }
        });
    }

    private void send(Channel ch, ResponseHandler responses, RequestSpec spec, ExchangeListener listener) {
        ch.eventLoop().execute(() -> {
            responses.expectResponse(listener);
            ch.writeAndFlush(request(spec)).addListener(ChannelFutureListener.FIRE_EXCEPTION_ON_FAILURE);
        });
    }

    private FullHttpRequest request(RequestSpec spec) {
        ByteBuf body = spec.post() ? Unpooled.wrappedBuffer(environment.bodyFiller(), 0, spec.bodyBytes()) : Unpooled.EMPTY_BUFFER;
        FullHttpRequest request = new DefaultFullHttpRequest(
                HttpVersion.HTTP_1_1, spec.post() ? HttpMethod.POST : HttpMethod.GET, spec.uri(), body);
        request.headers()
                .set(HttpHeaderNames.HOST, environment.hostHeader())
                .set(HttpHeaderNames.USER_AGENT, "aegis-loadtest");
        if (spec.post()) {
            request.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/octet-stream");
            HttpUtil.setContentLength(request, spec.bodyBytes());
        }
        return request;
    }
}
