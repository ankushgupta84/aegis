package io.aegis.loadtest;

import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpObject;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpUtil;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.codec.http.LastHttpContent;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

/**
 * Answers every request with {@code 200} and the backend's name. The request body is released as
 * it streams in, so large uploads cost no memory. The answer waits until the whole request has
 * arrived, as a real origin's would.
 */
final class BackendHandler extends SimpleChannelInboundHandler<HttpObject> {

    private final String name;
    private final byte[] body;
    private final long delayNanos;
    private boolean keepAlive;

    BackendHandler(String name, long delayNanos) {
        this.name = name;
        this.body = (name + "\n").getBytes(StandardCharsets.UTF_8);
        this.delayNanos = delayNanos;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, HttpObject message) {
        if (message instanceof HttpRequest request) {
            keepAlive = HttpUtil.isKeepAlive(request);
        }
        if (message instanceof LastHttpContent) {
            boolean closeAfter = !keepAlive;
            if (delayNanos == 0) {
                respond(ctx, closeAfter);
            } else {
                ctx.executor().schedule(() -> respond(ctx, closeAfter), delayNanos, TimeUnit.NANOSECONDS);
            }
        }
    }

    private void respond(ChannelHandlerContext ctx, boolean closeAfter) {
        FullHttpResponse response = new DefaultFullHttpResponse(
                HttpVersion.HTTP_1_1, HttpResponseStatus.OK, Unpooled.wrappedBuffer(body));
        response.headers().set("X-Backend", name);
        HttpUtil.setContentLength(response, body.length);
        HttpUtil.setKeepAlive(response, !closeAfter);
        var written = ctx.writeAndFlush(response);
        if (closeAfter) {
            written.addListener(ChannelFutureListener.CLOSE);
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        ctx.close();
    }
}
