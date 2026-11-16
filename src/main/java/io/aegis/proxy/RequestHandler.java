package io.aegis.proxy;

import io.aegis.observe.Event;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpUtil;
import io.netty.handler.timeout.IdleStateEvent;
import io.netty.util.ReferenceCountUtil;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.TimeUnit;

/**
 * One client connection, one request at a time. A request is screened ({@link Screening}), then
 * either refused here or handed to an {@link UpstreamExchange}; either way exactly one {@code request}
 * event and one set of metrics are written when it ends.
 *
 * <p>While a request is in flight the connection stops reading, so responses cannot be reordered.
 * Requests that a client pipelined into the same read are held and served in order afterwards.
 */
final class RequestHandler extends ChannelInboundHandlerAdapter {

    private static final long LINGER_SECONDS = 2;

    private final Screening screening;
    private final Telemetry telemetry;
    private final Drain drain;
    private final boolean viaTls;
    private final Deque<FullHttpRequest> waiting = new ArrayDeque<>();

    private ChannelHandlerContext ctx;
    private InetAddress peer;
    private FullHttpRequest current;
    private RequestRecord record;
    private UpstreamExchange exchange;
    private boolean answered;
    private boolean lingering;

    RequestHandler(Screening screening, Telemetry telemetry, Drain drain, boolean viaTls) {
        this.screening = screening;
        this.telemetry = telemetry;
        this.drain = drain;
        this.viaTls = viaTls;
    }

    // ---- connection events ------------------------------------------------------------------------

    @Override
    public void handlerAdded(ChannelHandlerContext context) {
        ctx = context;
        // Read once: a closed channel no longer reports its remote address.
        peer = context.channel().remoteAddress() instanceof InetSocketAddress address ? address.getAddress() : null;
        drain.register(this);
    }

    @Override
    public void channelRead(ChannelHandlerContext context, Object message) {
        if (lingering) {
            ReferenceCountUtil.release(message);
            return;
        }
        if (!(message instanceof FullHttpRequest request)) {
            ReferenceCountUtil.release(message);
            context.close();
            return;
        }
        if (current != null) {
            waiting.add(request);
        } else {
            begin(request);
        }
    }

    @Override
    public void channelInactive(ChannelHandlerContext context) {
        drain.unregister(this);
        if (current != null) {
            if (exchange != null) {
                exchange.cancel();
            }
            if (!answered) {
                record.decision = Decision.CLIENT_ABORTED;
            }
            finish(false);
        }
        releaseWaiting();
        context.fireChannelInactive();
    }

    @Override
    public void channelWritabilityChanged(ChannelHandlerContext context) {
        if (context.channel().isWritable() && exchange != null) {
            exchange.onClientWritable();
        }
        context.fireChannelWritabilityChanged();
    }

    @Override
    public void userEventTriggered(ChannelHandlerContext context, Object event) {
        if (event instanceof IdleStateEvent && current == null) {
            context.close();
        }
        context.fireUserEventTriggered(event);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext context, Throwable cause) {
        if (cause instanceof RefusedException refused) {
            refuseOutsideARequest(refused);
            return;
        }
        Throwable root = cause;
        while (root.getCause() != null) {
            root = root.getCause();
        }
        telemetry.metrics().connectionError(root);
        if (!(root instanceof IOException)) {
            telemetry.events().write(Event.of("connection_error")
                    .with("peer_ip", peer == null ? null : peer.getHostAddress())
                    .with("cause", root.getClass().getName())
                    .with("detail", root.getMessage()));
        }
        context.close();
    }

    /** Called from {@link Drain#begin} on any thread. */
    void closeIfIdle() {
        ctx.executor().execute(() -> {
            if (current == null) {
                ctx.close();
            }
        });
    }

    // ---- one request ------------------------------------------------------------------------------

    private void begin(FullHttpRequest request) {
        current = request;
        answered = false;
        record = new RequestRecord(peer);
        record.requestBytes = request.content().readableBytes();
        drain.requestStarted();
        ctx.channel().config().setAutoRead(false);
        try {
            switch (screening.screen(request, record)) {
                case Screening.Refused refused -> refuse(refused.refusal());
                case Screening.Admitted admitted -> forward(admitted.route());
            }
        } catch (RuntimeException e) {
            if (exchange != null) {
                exchange.cancel();
            }
            telemetry.events().write(Event.of("internal_error")
                    .with("request_id", record.id)
                    .with("cause", e.getClass().getName())
                    .with("detail", e.getMessage()));
            refuse(Refusal.internalError(e.getClass().getSimpleName()));
        }
    }

    private void forward(Route route) {
        exchange = new UpstreamExchange(route, current, record, ctx.channel(), viaTls, this::keepAlive, telemetry,
                new UpstreamExchange.Outcome() {
                    @Override
                    public void completed(boolean keepClientConnection) {
                        answered = true;
                        finish(keepClientConnection);
                    }

                    @Override
                    public void refused(Refusal refusal) {
                        refuse(refusal);
                    }

                    @Override
                    public void aborted(Decision decision) {
                        record.decision = decision;
                        finish(false);
                    }
                });
        exchange.start();
    }

    private void refuse(Refusal refusal) {
        answered = true;
        record.decision = refusal.decision();
        record.status = refusal.status().code();
        record.reason = refusal.reason();
        boolean keep = keepAlive() && !refusal.closeConnection();
        boolean head = current.method().equals(HttpMethod.HEAD);
        ctx.writeAndFlush(refusal.response(record.id, keep, head))
                .addListener(written -> finish(written.isSuccess() && keep));
    }

    private boolean keepAlive() {
        return HttpUtil.isKeepAlive(current) && !drain.isDraining();
    }

    /** Ends the request: log it, count it, release it, and serve the next or close. */
    private void finish(boolean keepConnection) {
        if (current == null) {
            return;
        }
        log(record);
        current.release();
        current = null;
        exchange = null;
        drain.requestFinished();
        if (!keepConnection) {
            closeConnection();
            releaseWaiting();
            return;
        }
        FullHttpRequest next = waiting.poll();
        if (next != null) {
            begin(next);
        } else {
            ctx.channel().config().setAutoRead(true);
        }
    }

    /** A refusal raised by an earlier handler, such as an oversize body or a slow head. */
    private void refuseOutsideARequest(RefusedException refused) {
        if (current != null) {
            ctx.close(); // the in-flight request is logged as aborted when the channel goes inactive
            return;
        }
        RequestRecord orphan = new RequestRecord(peer);
        orphan.method = refused.method();
        orphan.rawTarget = refused.target();
        Refusal refusal = refused.refusal();
        answered = true;
        orphan.decision = refusal.decision();
        orphan.status = refusal.status().code();
        orphan.reason = refusal.reason();
        ctx.writeAndFlush(refusal.response(orphan.id, false, false)).addListener(written -> closeConnection());
        log(orphan);
    }

    /**
     * Closing a socket that still has unread input makes the kernel reset the connection, and the
     * reset can destroy the response before the client reads it. So after a complete response on a
     * plain socket, stop sending, discard what the client is still sending, and close after a
     * short grace period (a lingering close). TLS connections close at once.
     */
    private void closeConnection() {
        Channel channel = ctx.channel();
        boolean cleanEnd = answered && channel.isActive() && !viaTls && channel instanceof SocketChannel;
        if (!cleanEnd) {
            ctx.close();
            return;
        }
        lingering = true;
        channel.config().setAutoRead(true);
        ((SocketChannel) channel).shutdownOutput();
        ctx.executor().schedule(() -> {
            channel.close();
        }, LINGER_SECONDS, TimeUnit.SECONDS);
    }

    private void log(RequestRecord finished) {
        telemetry.events().write(RequestLog.event(finished, telemetry.redactor()));
        telemetry.metrics().requestFinished(finished.routeName, finished.decision, System.nanoTime() - finished.startNanos);
    }

    private void releaseWaiting() {
        FullHttpRequest queued;
        while ((queued = waiting.poll()) != null) {
            queued.release();
        }
    }
}
