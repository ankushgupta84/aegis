package io.aegis.observe;

import io.aegis.plugin.LogSink;
import io.aegis.policy.LogSettings;
import java.io.IOException;
import java.io.PrintStream;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Writes events as JSON lines to rotating local files and hands each line to the log sinks.
 *
 * <p>Callers sit on event-loop threads, so {@link #write} only enqueues. One writer thread
 * drains a bounded queue. When the queue is full the event is dropped and counted, because a
 * slow disk must never stall the data path; the writer then logs a {@code log_events_dropped}
 * event with the count, because silent loss is not acceptable: a gap in the log is itself logged.
 * Closing the log also closes the sinks it was given.
 */
public final class EventLog implements AutoCloseable {

    static final int QUEUE_CAPACITY = 65_536;

    private sealed interface Item {}

    private record Queued(Event event, Instant at) implements Item {}

    private record Flush(CountDownLatch done) implements Item {}

    private record Stop() implements Item {}

    private final BlockingQueue<Item> queue;
    private final RotatingFile file;
    private final List<LogSink> sinks;
    private final Clock clock;
    private final EventJson json = new EventJson();
    private final FailureReporter failures;
    private final Thread writer = new Thread(this::drain, "aegis-event-log");

    private final AtomicLong droppedEvents = new AtomicLong();
    private final AtomicLong sinkFailures = new AtomicLong();
    private final AtomicLong writeFailures = new AtomicLong();
    private long reportedDrops; // writer thread only
    private volatile boolean closed;

    public EventLog(LogSettings settings, List<LogSink> sinks, Clock clock) {
        this(settings, sinks, clock, QUEUE_CAPACITY, System.err);
    }

    /** Lets tests use a tiny queue and capture what would go to standard error. */
    EventLog(LogSettings settings, List<LogSink> sinks, Clock clock, int queueCapacity, PrintStream err) {
        if (settings.rotateAtBytes() <= 0 || settings.keepFiles() < 0) {
            throw new IllegalArgumentException("Log rotateAtBytes must be positive and keepFiles non-negative, got "
                    + settings.rotateAtBytes() + " and " + settings.keepFiles());
        }
        this.queue = new ArrayBlockingQueue<>(queueCapacity);
        this.sinks = List.copyOf(sinks);
        this.clock = clock;
        this.failures = new FailureReporter(clock, err);
        try {
            this.file = new RotatingFile(settings.directory(), settings.rotateAtBytes(), settings.keepFiles());
        } catch (IOException e) {
            throw new IllegalStateException("Cannot create log directory " + settings.directory(), e);
        }
        writer.setDaemon(true);
        writer.start();
    }

    /** Queues the event without blocking; a full queue drops it and counts the loss. */
    public void write(Event event) {
        if (closed || !queue.offer(new Queued(event, clock.instant()))) {
            droppedEvents.incrementAndGet();
        }
    }

    public long droppedEvents() {
        return droppedEvents.get();
    }

    public long sinkFailures() {
        return sinkFailures.get();
    }

    /** Events that could not be serialized or written to the local file. */
    public long writeFailures() {
        return writeFailures.get();
    }

    /** Blocks until every event queued before the call is on disk. */
    public void flush() {
        if (closed) {
            return; // close() already drained the queue
        }
        CountDownLatch done = new CountDownLatch(1);
        enqueueBlocking(new Flush(done));
        awaitUninterruptibly(done);
    }

    @Override
    public void close() {
        if (closed) {
            return;
        }
        closed = true;
        enqueueBlocking(new Stop());
        joinUninterruptibly();
        closeFile();
        closeSinks();
    }

    private void drain() {
        try {
            while (true) {
                Item item = queue.take();
                switch (item) {
                    case Queued q -> {
                        reportDrops();
                        store(q.event(), q.at());
                        if (queue.isEmpty()) {
                            flushFile();
                        }
                    }
                    case Flush f -> {
                        reportDrops();
                        flushFile();
                        f.done().countDown();
                    }
                    case Stop s -> {
                        reportDrops();
                        flushFile();
                        return;
                    }
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void reportDrops() {
        long total = droppedEvents.get();
        if (total > reportedDrops) {
            Event marker = Event.of("log_events_dropped").with("count", total - reportedDrops);
            reportedDrops = total;
            store(marker, clock.instant());
        }
    }

    private void store(Event event, Instant at) {
        String line;
        try {
            line = json.line(event, at);
        } catch (IOException e) {
            failLocalWrite("cannot serialize " + event.type() + " event", e);
            return;
        }
        try {
            file.appendLine(line);
        } catch (IOException e) {
            failLocalWrite("cannot write " + RotatingFile.NAME, e);
        }
        for (LogSink sink : sinks) {
            try {
                sink.accept(line);
            } catch (RuntimeException e) {
                sinkFailures.incrementAndGet();
            }
        }
    }

    private void flushFile() {
        try {
            file.flush();
        } catch (IOException e) {
            failLocalWrite("cannot flush " + RotatingFile.NAME, e);
        }
    }

    private void failLocalWrite(String what, IOException cause) {
        writeFailures.incrementAndGet();
        failures.report(what, cause);
    }

    private void closeFile() {
        try {
            file.close();
        } catch (IOException e) {
            failLocalWrite("cannot close " + RotatingFile.NAME, e);
        }
    }

    private void closeSinks() {
        for (LogSink sink : sinks) {
            try {
                sink.close();
            } catch (RuntimeException e) {
                sinkFailures.incrementAndGet();
            }
        }
    }

    private void enqueueBlocking(Item item) {
        boolean interrupted = false;
        while (true) {
            try {
                queue.put(item);
                break;
            } catch (InterruptedException e) {
                interrupted = true;
            }
        }
        if (interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    private static void awaitUninterruptibly(CountDownLatch latch) {
        boolean interrupted = false;
        while (true) {
            try {
                latch.await();
                break;
            } catch (InterruptedException e) {
                interrupted = true;
            }
        }
        if (interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    private void joinUninterruptibly() {
        boolean interrupted = false;
        while (true) {
            try {
                writer.join();
                break;
            } catch (InterruptedException e) {
                interrupted = true;
            }
        }
        if (interrupted) {
            Thread.currentThread().interrupt();
        }
    }
}
