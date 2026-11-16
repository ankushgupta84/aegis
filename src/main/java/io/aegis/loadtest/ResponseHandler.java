package io.aegis.loadtest;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.HttpObject;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.HttpUtil;
import io.netty.handler.codec.http.LastHttpContent;

/**
 * Reports the status of the one response a connection is waiting for, and the cause if it never
 * comes. The body is discarded: the tester measures time, not content. Runs on the channel's
 * event loop only.
 */
final class ResponseHandler extends SimpleChannelInboundHandler<HttpObject> {

    private ExchangeListener listener;
    private int status;

    /** Starts waiting for a response; there is never more than one in flight per connection. */
    void expectResponse(ExchangeListener newListener) {
        listener = newListener;
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, HttpObject message) {
        if (message instanceof HttpResponse response) {
            status = response.status().code();
            if (!HttpUtil.isKeepAlive(response)) {
                // Closing now, not on the server's FIN, keeps the next request off a dying connection.
                ctx.close();
            }
        }
        if (message instanceof LastHttpContent) {
            ExchangeListener done = listener;
            listener = null;
            if (done != null) {
                done.completed(status);
            }
        }
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        fail(ErrorCause.CONNECTION_CLOSED);
        ctx.fireChannelInactive();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        fail(ErrorCause.of(cause));
        ctx.close();
    }

    private void fail(ErrorCause cause) {
        ExchangeListener failed = listener;
        listener = null;
        if (failed != null) {
            failed.failed(cause);
        }
    }
}
