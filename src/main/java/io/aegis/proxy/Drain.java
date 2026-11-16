package io.aegis.proxy;

import java.time.Duration;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Shutdown coordination. Counts requests in flight, knows every client connection, and lets
 * {@link AegisServer#close} stop new work, close idle connections, and wait for the rest.
 */
final class Drain {

    private final Set<RequestHandler> connections = ConcurrentHashMap.newKeySet();
    private final Object monitor = new Object();
    private int inFlight;
    private volatile boolean draining;

    boolean isDraining() {
        return draining;
    }

    void register(RequestHandler connection) {
        connections.add(connection);
    }

    void unregister(RequestHandler connection) {
        connections.remove(connection);
    }

    void requestStarted() {
        synchronized (monitor) {
            inFlight++;
        }
    }

    void requestFinished() {
        synchronized (monitor) {
            inFlight--;
            monitor.notifyAll();
        }
    }

    /** From now on responses carry {@code Connection: close}; connections with no request in flight close now. */
    void begin() {
        draining = true;
        connections.forEach(RequestHandler::closeIfIdle);
    }

    /** @return the requests still in flight when the wait ended; 0 means everything drained */
    int awaitIdle(Duration timeout) {
        long deadline = System.nanoTime() + timeout.toNanos();
        synchronized (monitor) {
            while (inFlight > 0) {
                long remainingMillis = (deadline - System.nanoTime()) / 1_000_000;
                if (remainingMillis <= 0) {
                    break;
                }
                try {
                    monitor.wait(remainingMillis);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
            return inFlight;
        }
    }
}
