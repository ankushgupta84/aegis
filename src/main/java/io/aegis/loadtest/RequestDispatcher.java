package io.aegis.loadtest;

import io.netty.channel.EventLoop;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;

/**
 * Hands due requests to idle connections, queues them when every connection is busy, enforces the
 * per-request timeout, and records each outcome. A request that waits in the queue keeps its
 * intended send time, so queueing delay shows up in its latency instead of disappearing.
 *
 * <p>All state belongs to the driver event loop. Connections complete on their own loops and hop
 * back with {@link EventLoop#execute}, which avoids locks and keeps the measurements consistent.
 */
final class RequestDispatcher {

    private final EventLoop driver;
    private final ClientEnvironment environment;
    private final long timeoutNanos;
    private final Measurements measurements;
    private final Runnable afterSettled;
    private final LongSupplier nanoClock;
    private final Deque<ClientConnection> idle = new ArrayDeque<>();
    private final Deque<PendingRequest> waiting = new ArrayDeque<>();
    private int waitingCount;
    private int unsettled;

    RequestDispatcher(EventLoop driver, ClientEnvironment environment, int connections, long timeoutNanos,
            Measurements measurements, LongSupplier nanoClock, Runnable afterSettled) {
        this.driver = driver;
        this.environment = environment;
        this.timeoutNanos = timeoutNanos;
        this.measurements = measurements;
        this.nanoClock = nanoClock;
        this.afterSettled = afterSettled;
        for (int i = 0; i < connections; i++) {
            idle.add(new ClientConnection(environment));
        }
    }

    int unsettled() {
        return unsettled;
    }

    void submit(PendingRequest request) {
        unsettled++;
        long untilDeadline = request.intendedNanos() + timeoutNanos - nanoClock.getAsLong();
        request.expireWith(driver.schedule(() -> fail(request, ErrorCause.TIMEOUT), untilDeadline, TimeUnit.NANOSECONDS));
        if (request.spec().newConnection()) {
            serve(request, new ClientConnection(environment));
            return;
        }
        waiting.add(request);
        waitingCount++;
        serveWaiting();
        if (request.recorded()) {
            measurements.queueDepth(waitingCount);
        }
    }

    void closeAll() {
        idle.forEach(ClientConnection::close);
    }

    private void serveWaiting() {
        while (!idle.isEmpty() && !waiting.isEmpty()) {
            PendingRequest next = waiting.poll();
            if (!next.isSettled()) {
                waitingCount--;
                serve(next, idle.poll());
            }
        }
    }

    private void serve(PendingRequest request, ClientConnection connection) {
        request.serveWith(connection);
        connection.execute(request.spec(), new ExchangeListener() {
            @Override
            public void completed(int status) {
                driver.execute(() -> succeed(request, status));
            }

            @Override
            public void failed(ErrorCause cause) {
                driver.execute(() -> fail(request, cause));
            }
        });
    }

    private void succeed(PendingRequest request, int status) {
        if (request.settle()) {
            if (request.recorded()) {
                measurements.response(request, status, nanoClock.getAsLong());
            }
            release(request, false);
        }
    }

    private void fail(PendingRequest request, ErrorCause cause) {
        if (request.settle()) {
            if (request.recorded()) {
                measurements.failure(request, cause, nanoClock.getAsLong());
            }
            release(request, true);
        }
    }

    /** A failed connection is closed because the state of its channel is unknown. */
    private void release(PendingRequest request, boolean discardChannel) {
        unsettled--;
        ClientConnection connection = request.connection();
        if (connection == null) {
            waitingCount--;
        } else if (request.spec().newConnection()) {
            connection.close();
        } else {
            if (discardChannel) {
                connection.close();
            }
            idle.add(connection);
            serveWaiting();
        }
        afterSettled.run();
    }
}
