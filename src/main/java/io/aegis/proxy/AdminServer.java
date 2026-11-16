package io.aegis.proxy;

import io.aegis.observe.Metrics;
import io.aegis.policy.Admin;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.codec.http.HttpUtil;
import io.netty.handler.codec.http.HttpVersion;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

/**
 * The admin listener: {@code GET /metrics} and {@code GET /healthz}, nothing else. It has its own
 * socket and thread and never carries proxied traffic, so a slow scrape cannot delay a request.
 * It changes nothing and has no authentication, so it belongs on localhost.
 */
final class AdminServer implements AutoCloseable {

    private static final String PROMETHEUS_TEXT = "text/plain; version=0.0.4; charset=utf-8";
    private static final int MAX_REQUEST_BYTES = 8192;

    private final EventLoopGroup group;
    private final Channel server;

    private AdminServer(EventLoopGroup group, Channel server) {
        this.group = group;
        this.server = server;
    }

    static AdminServer start(Admin admin, Metrics metrics, Transport transport) {
        EventLoopGroup group = transport.newGroup(1);
        try {
            Channel server = new ServerBootstrap()
                    .group(group)
                    .channel(transport.serverChannel())
                    .childHandler(new ChannelInitializer<Channel>() {
                        @Override
                        protected void initChannel(Channel channel) {
                            channel.pipeline().addLast(new HttpServerCodec(), new HttpObjectAggregator(MAX_REQUEST_BYTES),
                                    new Handler(metrics));
                        }
                    })
                    .bind(admin.bindAddress(), admin.port())
                    .syncUninterruptibly()
                    .channel();
            return new AdminServer(group, server);
        } catch (Exception e) {
            group.shutdownGracefully(0, 1, TimeUnit.SECONDS);
            throw new StartupException("Cannot listen on " + admin.bindAddress() + ":" + admin.port()
                    + " for the admin endpoint: " + e.getMessage(), e);
        }
    }

    int port() {
        return ((InetSocketAddress) server.localAddress()).getPort();
    }

    @Override
    public void close() {
        server.close().syncUninterruptibly();
        group.shutdownGracefully(0, 2, TimeUnit.SECONDS).syncUninterruptibly();
    }

    private static final class Handler extends SimpleChannelInboundHandler<FullHttpRequest> {

        private final Metrics metrics;

        Handler(Metrics metrics) {
            this.metrics = metrics;
        }

        @Override
        protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request) {
            send(ctx, answer(request));
        }

        private Answer answer(FullHttpRequest request) {
            if (request.decoderResult().isFailure()) {
                return new Answer(HttpResponseStatus.BAD_REQUEST, "text/plain; charset=utf-8", "bad request\n");
            }
            if (!request.method().equals(HttpMethod.GET)) {
                return new Answer(HttpResponseStatus.METHOD_NOT_ALLOWED, "text/plain; charset=utf-8", "method not allowed\n");
            }
            int question = request.uri().indexOf('?');
            String path = question < 0 ? request.uri() : request.uri().substring(0, question);
            return switch (path) {
                case "/metrics" -> new Answer(HttpResponseStatus.OK, PROMETHEUS_TEXT, metrics.scrape());
                case "/healthz" -> new Answer(HttpResponseStatus.OK, "text/plain; charset=utf-8", "ok");
                default -> new Answer(HttpResponseStatus.NOT_FOUND, "text/plain; charset=utf-8", "not found\n");
            };
        }

        private static void send(ChannelHandlerContext ctx, Answer answer) {
            FullHttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1, answer.status,
                    Unpooled.copiedBuffer(answer.body, StandardCharsets.UTF_8));
            response.headers().set(HttpHeaderNames.CONTENT_TYPE, answer.contentType);
            response.headers().set(HttpHeaderNames.ALLOW, "GET");
            HttpUtil.setContentLength(response, response.content().readableBytes());
            HttpUtil.setKeepAlive(response, false);
            ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
        }

        @Override
        public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
            ctx.close();
        }

        private record Answer(HttpResponseStatus status, String contentType, String body) {
        }
    }
}
