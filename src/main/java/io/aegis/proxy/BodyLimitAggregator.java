package io.aegis.proxy;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelPipeline;
import io.netty.handler.codec.http.HttpMessage;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpRequest;

/**
 * Buffers each request whole up to {@code listener.max_body_bytes}. Netty answers an oversize
 * request with a bare 413; this class hands the refusal to the request handler instead, so the
 * answer carries the incident ID and the refusal is logged and counted like any other.
 */
final class BodyLimitAggregator extends HttpObjectAggregator {

    BodyLimitAggregator(int maxBodyBytes) {
        super(maxBodyBytes);
    }

    /** Declines to send {@code 100 Continue} or Netty's own 413 for a body already known to be too long. */
    @Override
    protected Object newContinueResponse(HttpMessage start, int maxContentLength, ChannelPipeline pipeline) {
        return isContentLengthInvalid(start, maxContentLength) ? null : super.newContinueResponse(start, maxContentLength, pipeline);
    }

    @Override
    protected void handleOversizedMessage(ChannelHandlerContext ctx, HttpMessage oversized) {
        String method = oversized instanceof HttpRequest request ? request.method().name() : null;
        String target = oversized instanceof HttpRequest request ? request.uri() : null;
        ctx.fireExceptionCaught(new RefusedException(Refusal.bodyTooLarge(), method, target));
    }
}
