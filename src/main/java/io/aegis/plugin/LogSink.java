package io.aegis.plugin;

/**
 * Receives a copy of every event Aegis logs, for shipping to a store the operator already runs.
 * The local log files remain the source of truth; a sink that fails is logged and counted, and
 * never blocks or drops the local write.
 */
public interface LogSink extends AutoCloseable {

    /** @param jsonLine one event as a single line of JSON, without the trailing newline */
    void accept(String jsonLine);

    @Override
    void close();
}
