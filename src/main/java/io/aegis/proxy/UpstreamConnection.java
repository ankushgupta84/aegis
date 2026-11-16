package io.aegis.proxy;

import io.aegis.policy.BackendAddress;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.util.ReferenceCountUtil;

/**
 * One keep-alive connection to a backend, and the pipeline handler that serves it. While an
 * exchange is attached, everything the backend sends goes to it. While idle, the connection sits
 * in the pool: anything it receives then is a protocol violation, and a close or error just
 * removes it. Those idle events are not request failures, so they are not charged to anyone.
 *
 * <p>All methods run on the connection's event loop, which is the loop of the client that uses it.
 */
final class UpstreamConnection extends ChannelInboundHandlerAdapter {

    private final IdleConnections pool;
    private final BackendAddress backend;
    private Channel channel;
    private UpstreamExchange exchange;
    private boolean reused;
    private long idleSinceNanos;

    UpstreamConnection(IdleConnections pool, BackendAddress backend) {
        this.pool = pool;
        this.backend = backend;
    }

    Channel channel() {
        return channel;
    }

    /** True when the connection has served an earlier request, so the backend may have closed it meanwhile. */
    boolean reused() {
        return reused;
    }

    boolean isUsable(long maxIdleNanos) {
        return channel.isActive() && System.nanoTime() - idleSinceNanos < maxIdleNanos;
    }

    void attach(UpstreamExchange newExchange) {
        exchange = newExchange;
    }

    /** The exchange finished cleanly and the backend allows reuse: return the connection to the pool. */
    void release() {
        exchange = null;
        reused = true;
        channel.config().setAutoRead(true);
        idleSinceNanos = System.nanoTime();
        pool.put(backend, this);
    }

    /** The connection cannot be reused; any exchange loses it without being told. */
    void close() {
        exchange = null;
        channel.close();
    }

    @Override
    public void handlerAdded(ChannelHandlerContext ctx) {
        channel = ctx.channel();
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object message) {
        if (exchange == null) {
            ReferenceCountUtil.release(message);
            ctx.close();
            return;
        }
        exchange.onUpstreamMessage(message);
    }

    @Override
    public void channelReadComplete(ChannelHandlerContext ctx) {
        if (exchange != null) {
            exchange.onUpstreamReadComplete();
        }
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        if (exchange == null) {
            pool.forget(backend, this);
        } else {
            exchange.onUpstreamClosed();
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        if (exchange == null) {
            ctx.close();
        } else {
            exchange.onUpstreamError(cause);
        }
    }
}
