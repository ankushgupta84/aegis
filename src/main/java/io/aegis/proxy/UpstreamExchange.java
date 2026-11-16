package io.aegis.proxy;

import io.aegis.lb.RetryPolicy;
import io.aegis.observe.Event;
import io.aegis.policy.BackendAddress;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpContent;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpResponse;
import io.netty.handler.codec.http.HttpStatusClass;
import io.netty.handler.codec.http.HttpUtil;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.codec.http.LastHttpContent;
import io.netty.util.ReferenceCountUtil;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.FutureListener;
import io.netty.util.concurrent.ScheduledFuture;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

/**
 * One request's trip to a backend and the response's trip back: pick, connect, send, relay, and
 * at most one retry. It is a state machine driven by events on the client's event loop, so its
 * fields need no synchronization.
 *
 * <p>The rule that shapes it: once a response byte has gone to the client nothing can be retried or
 * replaced by an error page, so a failure from then on can only end the client's connection.
 * Before that, a failure is retried when {@link RetryPolicy} allows, else answered with 502 or 504.
 *
 * <p>The response is relayed as it arrives. When the client's socket cannot keep up, reading from
 * the backend stops until it can, so a slow client cannot make Aegis buffer a whole response.
 */
final class UpstreamExchange {

    /** How the exchange ended. Exactly one method is called, once, on the client's event loop. */
    interface Outcome {
        /** The whole response was written to the client. */
        void completed(boolean keepClientConnection);

        /** Nothing reached the client yet; answer with this refusal. */
        void refused(Refusal refusal);

        /** The response was cut short after it started; the client's connection must close. */
        void aborted(Decision decision);
    }

    private final Route route;
    private final FullHttpRequest request;
    private final RequestRecord record;
    private final Channel client;
    private final boolean viaTls;
    private final BooleanSupplier clientKeepAlive;
    private final boolean headRequest;
    private final boolean clientHttp11;
    private final Telemetry telemetry;
    private final Outcome outcome;
    private final long startNanos = System.nanoTime();

    private BackendAddress backend;
    private UpstreamConnection connection;
    private boolean requestSent;
    private boolean reconnected;
    private boolean retried;
    private boolean responseStarted;
    private boolean ignoringInterimResponse;
    private boolean backendKeepAlive;
    private boolean clientKeepsConnection;
    private int backendStatus;
    private boolean paused;
    private boolean finished;
    private ScheduledFuture<?> timeout;

    UpstreamExchange(Route route, FullHttpRequest request, RequestRecord record, Channel client, boolean viaTls,
            BooleanSupplier clientKeepAlive, Telemetry telemetry, Outcome outcome) {
        this.route = route;
        this.request = request;
        this.record = record;
        this.client = client;
        this.viaTls = viaTls;
        this.clientKeepAlive = clientKeepAlive;
        this.headRequest = request.method().equals(HttpMethod.HEAD);
        this.clientHttp11 = request.protocolVersion().equals(HttpVersion.HTTP_1_1);
        this.telemetry = telemetry;
        this.outcome = outcome;
    }

    void start() {
        route.balancer().pick().ifPresentOrElse(first -> attempt(first, true), () -> refuse(Refusal.noBackend()));
    }

    /** The client went away: abandon the backend connection, whose response nobody will read. */
    void cancel() {
        if (finished) {
            return;
        }
        finished = true;
        cancelTimeout();
        record.upstreamNanos = System.nanoTime() - startNanos;
        if (connection != null) {
            telemetry.metrics().backendAttempt(backend, "client_aborted");
            dropConnection();
        }
    }

    /** The client's socket drained below its low-water mark: resume reading the backend. */
    void onClientWritable() {
        if (paused && !finished && connection != null) {
            paused = false;
            connection.channel().config().setAutoRead(true);
            armTimeout();
        }
    }

    // ---- attempts -----------------------------------------------------------------------------

    private void attempt(BackendAddress target, boolean allowIdle) {
        backend = target;
        record.backend = target.toString();
        requestSent = false;
        FutureListener<UpstreamConnection> onAcquired = this::acquired;
        route.upstream().acquire(client.eventLoop(), target, allowIdle).addListener(onAcquired);
    }

    private void acquired(Future<UpstreamConnection> acquisition) {
        if (!acquisition.isSuccess()) {
            attemptFailed(UpstreamFailure.ofConnect(acquisition.cause()), true, acquisition.cause());
            return;
        }
        UpstreamConnection acquired = acquisition.getNow();
        if (finished) {
            acquired.close();
            return;
        }
        connection = acquired;
        connection.attach(this);
        send();
    }

    private void send() {
        FullHttpRequest out = UpstreamRequest.build(request, record.id, record.peer.getHostAddress(), viaTls);
        armTimeout();
        // Conservative: once handed to the socket, some bytes may have reached the backend.
        requestSent = true;
        Channel channel = connection.channel();
        channel.writeAndFlush(out).addListener((ChannelFuture written) -> {
            if (!written.isSuccess() && connection != null && connection.channel() == channel) {
                writeFailed(written.cause());
            }
        });
    }

    /**
     * A write that fails on a connection reused from the pool means the backend closed it while it
     * sat idle: nothing was sent, and the backend did nothing wrong. Try once on a fresh
     * connection to the same backend; this is not the load balancer's retry.
     */
    private void writeFailed(Throwable cause) {
        if (connection.reused() && !reconnected) {
            reconnected = true;
            cancelTimeout();
            dropConnection();
            attempt(backend, false);
            return;
        }
        attemptFailed(UpstreamFailure.CONNECTION_RESET, true, cause);
    }

    // ---- events from the backend ----------------------------------------------------------------

    void onUpstreamMessage(Object message) {
        if (finished || connection == null) {
            ReferenceCountUtil.release(message);
            return;
        }
        try {
            if (message instanceof HttpResponse head) {
                onHead(head);
            } else if (message instanceof HttpContent content) {
                onContent(content);
            } else {
                ReferenceCountUtil.release(message);
            }
        } catch (RuntimeException e) {
            internalFailure(e);
        }
    }

    /** A bug in relaying must end the request visibly: logged, and answered or cut off, never left hanging. */
    private void internalFailure(RuntimeException cause) {
        telemetry.events().write(Event.of("internal_error")
                .with("request_id", record.id)
                .with("cause", cause.getClass().getName())
                .with("detail", cause.getMessage()));
        if (finished) {
            client.close();
            return;
        }
        cancelTimeout();
        dropConnection();
        if (responseStarted) {
            finished = true;
            record.upstreamNanos = System.nanoTime() - startNanos;
            outcome.aborted(Decision.INTERNAL_ERROR);
        } else {
            refuse(Refusal.internalError(cause.getClass().getSimpleName()));
        }
    }

    void onUpstreamReadComplete() {
        if (!finished && responseStarted) {
            client.flush();
        }
    }

    void onUpstreamClosed() {
        failedByTransport(null);
    }

    void onUpstreamError(Throwable cause) {
        failedByTransport(cause);
    }

    /**
     * A reset or close before any response byte on a reused connection is most likely the backend
     * having closed it while idle, so it is not charged to the backend's health.
     */
    private void failedByTransport(Throwable cause) {
        if (finished || connection == null) {
            return;
        }
        boolean mayBeStale = connection.reused() && !responseStarted;
        attemptFailed(UpstreamFailure.CONNECTION_RESET, !mayBeStale, cause);
    }

    private void onHead(HttpResponse head) {
        if (head.decoderResult().isFailure()) {
            attemptFailed(UpstreamFailure.INVALID_RESPONSE, true, head.decoderResult().cause());
            return;
        }
        if (head.status().codeClass() == HttpStatusClass.INFORMATIONAL) {
            // We never ask for 100-continue, so an interim response is noise; its empty body follows.
            ignoringInterimResponse = true;
            return;
        }
        cancelTimeout();
        responseStarted = true;
        backendStatus = head.status().code();
        record.status = backendStatus;
        backendKeepAlive = HttpUtil.isKeepAlive(head);
        HttpResponse out = ResponseHead.forClient(head, headRequest, clientHttp11, clientKeepAlive.getAsBoolean(), record.id);
        clientKeepsConnection = HttpUtil.isKeepAlive(out);
        client.write(out).addListener(ChannelFutureListener.CLOSE_ON_FAILURE);
        armTimeout();
    }

    private void onContent(HttpContent content) {
        if (ignoringInterimResponse) {
            ignoringInterimResponse = !(content instanceof LastHttpContent);
            content.release();
            return;
        }
        record.responseBytes += content.content().readableBytes();
        if (content instanceof LastHttpContent last) {
            complete(last);
            return;
        }
        client.write(content).addListener(ChannelFutureListener.CLOSE_ON_FAILURE);
        if (client.isWritable()) {
            armTimeout();
        } else {
            paused = true;
            cancelTimeout();
            connection.channel().config().setAutoRead(false);
        }
    }

    private void complete(LastHttpContent last) {
        // Trailers are not relayed: the Trailer header was stripped, so the client was not told to expect them.
        if (!last.trailingHeaders().isEmpty()) {
            last.trailingHeaders().clear();
        }
        finished = true;
        cancelTimeout();
        UpstreamConnection used = connection;
        connection = null;
        if (backendKeepAlive && used.channel().isActive()) {
            used.release();
        } else {
            used.close();
        }
        accountForResponse();
        record.upstreamNanos = System.nanoTime() - startNanos;
        boolean keep = clientKeepsConnection;
        client.writeAndFlush(last).addListener((ChannelFuture flushed) -> outcome.completed(flushed.isSuccess() && keep));
    }

    private void accountForResponse() {
        boolean serverError = backendStatus >= 500;
        telemetry.metrics().backendAttempt(backend, serverError ? "server_error" : "success");
        if (serverError && route.policy().upstream().health().countServerErrors()) {
            chargeBackend(UpstreamFailure.SERVER_ERROR, null);
        } else {
            route.balancer().reportSuccess(backend);
        }
    }

    // ---- failure --------------------------------------------------------------------------------

    private void attemptFailed(UpstreamFailure failure, boolean charge, Throwable detail) {
        if (finished) {
            return;
        }
        cancelTimeout();
        dropConnection();
        telemetry.metrics().backendAttempt(backend, failure.label());
        if (charge) {
            chargeBackend(failure, detail);
        }
        if (responseStarted) {
            finished = true;
            record.upstreamNanos = System.nanoTime() - startNanos;
            outcome.aborted(failure.decision());
            return;
        }
        Optional<BackendAddress> other = mayRetry() ? route.balancer().pickOtherThan(backend) : Optional.empty();
        if (other.isPresent()) {
            retried = true;
            record.retried = true;
            attempt(other.get(), true);
        } else {
            refuse(failure.refusal());
        }
    }

    private boolean mayRetry() {
        return !retried && RetryPolicy.mayRetry(request.method().name(), requestSent);
    }

    private void chargeBackend(UpstreamFailure failure, Throwable detail) {
        boolean wasEjected = route.balancer().isEjected(backend);
        route.balancer().reportFailure(backend);
        telemetry.metrics().backendFailure(backend, failure.label());
        telemetry.events().write(Event.of("backend_failure")
                .with("request_id", record.id)
                .with("backend", backend.toString())
                .with("cause", failure.label())
                .with("detail", detail == null ? null : detail.getClass().getName() + ": " + detail.getMessage()));
        if (!wasEjected && route.balancer().isEjected(backend)) {
            telemetry.metrics().backendEjected(backend);
            telemetry.events().write(Event.of("backend_ejected")
                    .with("request_id", record.id)
                    .with("backend", backend.toString())
                    .with("route", route.name()));
        }
    }

    private void refuse(Refusal refusal) {
        finished = true;
        record.upstreamNanos = System.nanoTime() - startNanos;
        outcome.refused(refusal);
    }

    // ---- plumbing ---------------------------------------------------------------------------------

    private void dropConnection() {
        if (connection != null) {
            connection.close();
            connection = null;
        }
    }

    private void armTimeout() {
        cancelTimeout();
        long millis = route.policy().upstream().responseTimeout().toMillis();
        timeout = client.eventLoop().schedule(this::timedOut, millis, TimeUnit.MILLISECONDS);
    }

    private void cancelTimeout() {
        if (timeout != null) {
            timeout.cancel(false);
            timeout = null;
        }
    }

    private void timedOut() {
        timeout = null;
        attemptFailed(UpstreamFailure.RESPONSE_TIMEOUT, true, null);
    }
}
