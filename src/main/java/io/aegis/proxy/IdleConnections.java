package io.aegis.proxy;

import io.aegis.policy.BackendAddress;
import java.util.ArrayDeque;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Idle keep-alive connections of one event loop, per backend. Touched only by that loop's thread,
 * so there is no locking. The most recently used connection is handed out first: it is the one
 * least likely to have been closed by the backend meanwhile.
 */
final class IdleConnections {

    static final int MAX_PER_BACKEND = 32;
    /** Backends commonly close idle connections after a few seconds; do not trust an old one. */
    static final long MAX_IDLE_NANOS = TimeUnit.SECONDS.toNanos(15);

    private final Map<BackendAddress, ArrayDeque<UpstreamConnection>> idle = new HashMap<>();

    /** A live connection that has been idle for less than the limit, or null. Dead and old ones are closed. */
    UpstreamConnection take(BackendAddress backend) {
        ArrayDeque<UpstreamConnection> connections = idle.get(backend);
        while (connections != null && !connections.isEmpty()) {
            UpstreamConnection candidate = connections.pollLast();
            if (candidate.isUsable(MAX_IDLE_NANOS)) {
                return candidate;
            }
            candidate.close();
        }
        return null;
    }

    void put(BackendAddress backend, UpstreamConnection connection) {
        ArrayDeque<UpstreamConnection> connections = idle.computeIfAbsent(backend, b -> new ArrayDeque<>());
        if (connections.size() >= MAX_PER_BACKEND) {
            connection.close();
            return;
        }
        connections.addLast(connection);
    }

    void forget(BackendAddress backend, UpstreamConnection connection) {
        ArrayDeque<UpstreamConnection> connections = idle.get(backend);
        if (connections != null) {
            connections.remove(connection);
        }
    }
}
