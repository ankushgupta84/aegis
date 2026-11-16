package io.aegis.loadtest;

import io.netty.channel.DefaultEventLoop;
import io.netty.channel.EventLoop;
import io.netty.channel.EventLoopGroup;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

/**
 * One load run: emits requests on the fixed schedule from a dedicated driver thread that does no
 * network I/O, so a slow socket cannot delay the schedule. Blocks until every request has
 * settled, which the per-request timeout bounds.
 */
final class LoadRun {

    private static final int MAX_IO_THREADS = 4;

    private final LoadTestOptions options;
    private final EventLoop driver = new DefaultEventLoop();
    private final CompletableFuture<Report> finished = new CompletableFuture<>();
    private final RequestMix mix;
    private final Measurements measurements;
    private final long totalRequests;
    private final long warmupRequests;
    private RequestDispatcher dispatcher;
    private SendSchedule schedule;
    private long nextIndex;

    private LoadRun(LoadTestOptions options) {
        this.options = options;
        this.mix = new RequestMix(options);
        this.measurements = new Measurements(options.timeout().toNanos());
        this.warmupRequests = requestsIn(options.warmup());
        this.totalRequests = warmupRequests + requestsIn(options.duration());
    }

    static Report execute(LoadTestOptions options) throws Exception {
        return new LoadRun(options).run();
    }

    private Report run() throws Exception {
        Transport transport = Transport.best();
        EventLoopGroup io = transport.newGroup(Math.min(MAX_IO_THREADS, Runtime.getRuntime().availableProcessors()));
        try {
            ClientEnvironment environment = ClientEnvironment.create(options, transport, io);
            dispatcher = new RequestDispatcher(driver, environment, options.connections(),
                    options.timeout().toNanos(), measurements, System::nanoTime, this::finishIfSettled);
            schedule = new SendSchedule(System.nanoTime(), options.rate());
            driver.execute(this::emitDue);
            return finished.get();
        } catch (ExecutionException e) {
            throw e.getCause() instanceof Exception cause ? cause : e;
        } finally {
            if (dispatcher != null) {
                driver.submit(dispatcher::closeAll).syncUninterruptibly();
            }
            io.shutdownGracefully(0, 1, TimeUnit.SECONDS).syncUninterruptibly();
            driver.shutdownGracefully(0, 1, TimeUnit.SECONDS).syncUninterruptibly();
        }
    }

    /** Sends everything due now, then sleeps until the next request is due. */
    private void emitDue() {
        long now = System.nanoTime();
        while (nextIndex < totalRequests && schedule.intendedAt(nextIndex) <= now) {
            dispatcher.submit(new PendingRequest(mix.next(), schedule.intendedAt(nextIndex), nextIndex >= warmupRequests));
            nextIndex++;
        }
        if (nextIndex < totalRequests) {
            driver.schedule(this::emitDue, schedule.intendedAt(nextIndex) - System.nanoTime(), TimeUnit.NANOSECONDS);
        } else {
            finishIfSettled();
        }
    }

    private void finishIfSettled() {
        if (nextIndex == totalRequests && dispatcher.unsettled() == 0) {
            finished.complete(measurements.report(options, warmupRequests));
        }
    }

    private long requestsIn(Duration span) {
        return options.rate() * span.toMillis() / 1000;
    }
}
