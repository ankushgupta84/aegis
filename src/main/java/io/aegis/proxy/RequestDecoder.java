package io.aegis.proxy;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.HttpDecoderConfig;
import io.netty.handler.codec.http.HttpMessage;
import io.netty.handler.codec.http.HttpRequest;
import io.netty.handler.codec.http.HttpRequestDecoder;
import io.netty.handler.codec.http.LastHttpContent;
import io.netty.util.concurrent.ScheduledFuture;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Netty's request decoder with the three changes a security proxy needs.
 *
 * <ul>
 *   <li>A request with both {@code Content-Length} and {@code Transfer-Encoding: chunked} is invalid.
 *       Netty's default silently drops the length, which would hide the smuggling attempt from
 *       {@code FramingCheck}.
 *   <li>The request line is decoded as ISO-8859-1, one char per byte, which {@code ParsedRequest}
 *       requires. Netty's default decodes US-ASCII and turns other bytes into U+FFFD.
 *   <li>The head must arrive within {@code listener.header_timeout} of its first byte, or the
 *       request handler is asked to refuse with 408. An idle keep-alive connection is not affected:
 *       the clock starts with the first byte, not with the connection.
 * </ul>
 */
final class RequestDecoder extends HttpRequestDecoder {

    private final long headerTimeoutMillis;
    private boolean awaitingHead = true;
    private ScheduledFuture<?> deadline;

    RequestDecoder(HttpDecoderConfig config, Duration headerTimeout) {
        super(config);
        this.headerTimeoutMillis = headerTimeout.toMillis();
    }

    @Override
    protected void handleTransferEncodingChunkedWithContentLength(HttpMessage message) {
        throw new IllegalArgumentException("The request has both Content-Length and Transfer-Encoding, so its length is ambiguous.");
    }

    @Override
    protected String splitFirstWordInitialLine(byte[] bytes, int start, int length) {
        return new String(bytes, start, length, StandardCharsets.ISO_8859_1);
    }

    @Override
    protected String splitSecondWordInitialLine(byte[] bytes, int start, int length) {
        return new String(bytes, start, length, StandardCharsets.ISO_8859_1);
    }

    @Override
    protected String splitThirdWordInitialLine(byte[] bytes, int start, int length) {
        return new String(bytes, start, length, StandardCharsets.ISO_8859_1);
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf buffer, List<Object> out) throws Exception {
        if (awaitingHead && deadline == null && buffer.isReadable()) {
            deadline = ctx.executor().schedule(() -> expire(ctx), headerTimeoutMillis, TimeUnit.MILLISECONDS);
        }
        int before = out.size();
        super.decode(ctx, buffer, out);
        for (int i = before; i < out.size(); i++) {
            observe(out.get(i));
        }
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        cancelDeadline();
        super.channelInactive(ctx);
    }

    private void observe(Object decoded) {
        if (decoded instanceof HttpRequest) {
            awaitingHead = false;
            cancelDeadline();
        }
        if (decoded instanceof LastHttpContent) {
            awaitingHead = true;
        }
    }

    private void expire(ChannelHandlerContext ctx) {
        deadline = null;
        if (awaitingHead && ctx.channel().isActive()) {
            ctx.fireExceptionCaught(new RefusedException(Refusal.headerTimeout(), null, null));
        }
    }

    private void cancelDeadline() {
        if (deadline != null) {
            deadline.cancel(false);
            deadline = null;
        }
    }
}
