package io.aegis.observe;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.aegis.plugin.LogSink;
import io.aegis.policy.LogSettings;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class EventLogTest {

    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-01-01T00:00:00.123Z"), ZoneOffset.UTC);
    private static final ObjectMapper JSON = new ObjectMapper();

    @TempDir
    Path dir;

    private final ByteArrayOutputStream stderr = new ByteArrayOutputStream();

    private EventLog log(long rotateAtBytes, int keepFiles, List<LogSink> sinks, int queueCapacity) {
        LogSettings settings = new LogSettings(dir.resolve("logs"), rotateAtBytes, keepFiles, List.of());
        return new EventLog(settings, sinks, CLOCK, queueCapacity, new PrintStream(stderr, true, StandardCharsets.UTF_8));
    }

    private EventLog log() {
        return log(1_000_000, 3, List.of(), EventLog.QUEUE_CAPACITY);
    }

    private List<String> lines(String fileName) throws IOException {
        return Files.readAllLines(dir.resolve("logs").resolve(fileName));
    }

    @Test
    void event_is_one_json_line_with_timestamp_type_then_fields_in_insertion_order() throws Exception {
        try (EventLog log = log()) {
            log.write(Event.of("request").with("status", 200).with("method", "GET").with("ok", true));
            log.flush();
        }

        assertThat(lines("aegis.log")).containsExactly(
                "{\"ts\":\"2026-01-01T00:00:00.123Z\",\"type\":\"request\",\"status\":200,\"method\":\"GET\",\"ok\":true}");
    }

    @Test
    void timestamp_keeps_three_digit_milliseconds_even_when_zero() throws Exception {
        Clock whole = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);
        LogSettings settings = new LogSettings(dir.resolve("logs"), 1_000_000, 1, List.of());
        try (EventLog log = new EventLog(settings, List.of(), whole)) {
            log.write(Event.of("t"));
            log.flush();
        }

        assertThat(lines("aegis.log")).containsExactly("{\"ts\":\"2026-01-01T00:00:00.000Z\",\"type\":\"t\"}");
    }

    @Test
    void null_fields_are_omitted() throws Exception {
        try (EventLog log = log()) {
            log.write(Event.of("t").with("a", null).with("b", 1));
            log.flush();
        }

        assertThat(lines("aegis.log").get(0)).doesNotContain("\"a\"").contains("\"b\":1");
    }

    @Test
    void nested_lists_and_maps_are_serialized() throws Exception {
        try (EventLog log = log()) {
            log.write(Event.of("t").with("rules", List.of(1, 2)).with("headers", Map.of("host", "x")));
            log.flush();
        }

        JsonNode event = JSON.readTree(lines("aegis.log").get(0));
        assertThat(event.get("rules")).hasSize(2);
        assertThat(event.get("headers").get("host").asText()).isEqualTo("x");
    }

    @Test
    void newlines_in_values_cannot_split_a_line() throws Exception {
        try (EventLog log = log()) {
            log.write(Event.of("t").with("agent", "a\nb"));
            log.flush();
        }

        assertThat(lines("aegis.log")).hasSize(1);
    }

    @Test
    void reserved_and_duplicate_field_names_are_rejected() {
        assertThatThrownBy(() -> Event.of("t").with("ts", 1)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Event.of("t").with("type", "x")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Event.of("t").with("a", 1).with("a", 2)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void directory_is_created_when_missing() throws Exception {
        try (EventLog log = log()) {
            log.flush();
        }

        assertThat(dir.resolve("logs")).isDirectory();
    }

    @Test
    void file_rotates_at_the_size_limit_and_keeps_only_the_newest_rotated_files() throws Exception {
        String line = "{\"ts\":\"2026-01-01T00:00:00.123Z\",\"type\":\"t\",\"n\":1}\n";
        try (EventLog log = log(2L * line.length(), 2, List.of(), EventLog.QUEUE_CAPACITY)) {
            for (int n = 1; n <= 7; n++) {
                log.write(Event.of("t").with("n", n));
            }
            log.flush();
        }

        assertThat(lines("aegis.log")).hasSize(1).allMatch(l -> l.endsWith("\"n\":7}"));
        assertThat(numbers(lines("aegis.log.1"))).containsExactly(5, 6);
        assertThat(numbers(lines("aegis.log.2"))).containsExactly(3, 4);
        assertThat(dir.resolve("logs").resolve("aegis.log.3")).doesNotExist();
        assertThat(Files.list(dir.resolve("logs")).count()).isEqualTo(3);
    }

    @Test
    void keeping_zero_files_discards_a_full_log() throws Exception {
        try (EventLog log = log(1, 0, List.of(), EventLog.QUEUE_CAPACITY)) {
            log.write(Event.of("t"));
            log.flush();
        }

        assertThat(Files.list(dir.resolve("logs")).count()).isZero();
    }

    @Test
    void an_existing_log_is_appended_to_and_counted_toward_rotation() throws Exception {
        Files.createDirectories(dir.resolve("logs"));
        Files.writeString(dir.resolve("logs").resolve("aegis.log"), "old\n");

        try (EventLog log = log(10, 1, List.of(), EventLog.QUEUE_CAPACITY)) {
            log.write(Event.of("t"));
            log.flush();
        }

        assertThat(lines("aegis.log.1")).hasSize(2).first().isEqualTo("old");
    }

    @Test
    void full_queue_drops_events_and_the_writer_logs_how_many() throws Exception {
        BlockingSink sink = new BlockingSink();
        try (EventLog log = log(1_000_000, 1, List.of(sink), 2)) {
            log.write(Event.of("t").with("n", 0));
            sink.entered.await(); // the writer is now stuck inside the sink, off the queue
            log.write(Event.of("t").with("n", 1));
            log.write(Event.of("t").with("n", 2));
            log.write(Event.of("t").with("n", 3));
            log.write(Event.of("t").with("n", 4));
            assertThat(log.droppedEvents()).isEqualTo(2);

            sink.release.countDown();
            log.flush();

            assertThat(log.droppedEvents()).isEqualTo(2);
        }

        List<String> written = lines("aegis.log");
        assertThat(written).hasSize(4);
        JsonNode marker = JSON.readTree(written.get(1));
        assertThat(marker.get("type").asText()).isEqualTo("log_events_dropped");
        assertThat(marker.get("count").asInt()).isEqualTo(2);
        assertThat(written.stream().filter(l -> l.contains("log_events_dropped"))).hasSize(1);
    }

    @Test
    void drops_after_a_marker_produce_a_second_marker_for_only_the_new_losses() throws Exception {
        BlockingSink sink = new BlockingSink();
        try (EventLog log = log(1_000_000, 1, List.of(sink), 1)) {
            log.write(Event.of("t"));
            sink.entered.await();
            log.write(Event.of("t"));
            log.write(Event.of("t")); // dropped
            sink.release.countDown();
            log.flush();
            log.write(Event.of("t"));
            log.flush();
        }

        List<JsonNode> markers = new ArrayList<>();
        for (String l : lines("aegis.log")) {
            JsonNode node = JSON.readTree(l);
            if (node.get("type").asText().equals("log_events_dropped")) {
                markers.add(node);
            }
        }
        assertThat(markers).hasSize(1);
        assertThat(markers.get(0).get("count").asInt()).isEqualTo(1);
    }

    @Test
    void failing_sink_is_counted_and_blocks_neither_the_file_nor_other_sinks() throws Exception {
        List<String> received = new CopyOnWriteArrayList<>();
        LogSink broken = new RecordingSink(null) {
            @Override
            public void accept(String jsonLine) {
                throw new IllegalStateException("sink down");
            }
        };
        LogSink healthy = new RecordingSink(received);
        try (EventLog log = log(1_000_000, 1, List.of(broken, healthy), EventLog.QUEUE_CAPACITY)) {
            log.write(Event.of("a"));
            log.write(Event.of("b"));
            log.flush();

            assertThat(log.sinkFailures()).isEqualTo(2);
            assertThat(log.writeFailures()).isZero();
        }

        assertThat(lines("aegis.log")).hasSize(2);
        assertThat(received).isEqualTo(lines("aegis.log"));
    }

    @Test
    void closing_the_log_closes_its_sinks_and_later_writes_count_as_dropped() {
        List<String> none = new ArrayList<>();
        RecordingSink sink = new RecordingSink(none);
        EventLog log = log(1_000_000, 1, List.of(sink), EventLog.QUEUE_CAPACITY);

        log.close();
        log.write(Event.of("late"));

        assertThat(sink.closed).isTrue();
        assertThat(log.droppedEvents()).isEqualTo(1);
    }

    @Test
    void local_write_failure_is_counted_and_reported_once_per_minute() throws Exception {
        // A non-empty directory where the oldest rotated file belongs makes every rotation fail.
        Path blocker = dir.resolve("logs").resolve("aegis.log.1");
        Files.createDirectories(blocker);
        Files.writeString(blocker.resolve("x"), "x");
        List<String> received = new CopyOnWriteArrayList<>();

        try (EventLog log = log(1, 1, List.of(new RecordingSink(received)), EventLog.QUEUE_CAPACITY)) {
            log.write(Event.of("a"));
            log.write(Event.of("b"));
            log.flush();

            assertThat(log.writeFailures()).isEqualTo(2);
        }

        assertThat(received).hasSize(2);
        String err = stderr.toString(StandardCharsets.UTF_8);
        assertThat(err.lines().count()).isEqualTo(1);
        assertThat(err).contains("cannot write aegis.log");
    }

    @Test
    void concurrent_writers_produce_exactly_n_well_formed_lines() throws Exception {
        int threads = 8;
        int perThread = 500;
        try (EventLog log = log()) {
            CountDownLatch start = new CountDownLatch(1);
            List<Thread> workers = new ArrayList<>();
            for (int t = 0; t < threads; t++) {
                int id = t;
                Thread worker = new Thread(() -> {
                    awaitQuietly(start);
                    for (int i = 0; i < perThread; i++) {
                        log.write(Event.of("t").with("id", id * perThread + i));
                    }
                });
                workers.add(worker);
                worker.start();
            }
            start.countDown();
            for (Thread worker : workers) {
                worker.join();
            }
            log.flush();

            assertThat(log.droppedEvents()).isZero();
        }

        Set<Integer> ids = new HashSet<>();
        for (String line : lines("aegis.log")) {
            ids.add(JSON.readTree(line).get("id").asInt());
        }
        assertThat(lines("aegis.log")).hasSize(threads * perThread);
        assertThat(ids).hasSize(threads * perThread);
    }

    @Test
    void invalid_rotation_settings_are_rejected() {
        assertThatThrownBy(() -> log(0, 1, List.of(), 1)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> log(1, -1, List.of(), 1)).isInstanceOf(IllegalArgumentException.class);
    }

    private static List<Integer> numbers(List<String> lines) throws IOException {
        List<Integer> numbers = new ArrayList<>();
        for (String line : lines) {
            numbers.add(JSON.readTree(line).get("n").asInt());
        }
        return numbers;
    }

    private static void awaitQuietly(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Holds the writer thread inside its first line until released, so the queue can be filled. */
    private static final class BlockingSink implements LogSink {
        final CountDownLatch entered = new CountDownLatch(1);
        final CountDownLatch release = new CountDownLatch(1);

        @Override
        public void accept(String jsonLine) {
            entered.countDown();
            awaitQuietly(release);
        }

        @Override
        public void close() {
        }
    }

    private static class RecordingSink implements LogSink {
        private final List<String> received;
        volatile boolean closed;

        RecordingSink(List<String> received) {
            this.received = received;
        }

        @Override
        public void accept(String jsonLine) {
            received.add(jsonLine);
        }

        @Override
        public void close() {
            closed = true;
        }
    }
}
