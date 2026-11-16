package io.aegis.proxy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.aegis.config.ConfigLoader;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;

/**
 * An {@link AegisServer} booted in-process from a configuration assembled out of small pieces, so
 * each test states only what makes it different. Plain HTTP, ephemeral ports, loopback proxies
 * trusted so tests can pick a client address with {@code X-Forwarded-For}, rate limit off.
 */
final class TestProxy implements AutoCloseable {

    static final Path TEST_RULES = Path.of("src/test/resources/proxy/test.rules").toAbsolutePath();
    static final Path MONITOR_RULES = Path.of("src/test/resources/proxy/monitor.rules").toAbsolutePath();
    private static final ObjectMapper JSON = new ObjectMapper();

    /** Collects the pieces of a configuration. */
    static final class Config {
        private final Path dir;
        private final List<Integer> backendPorts = new ArrayList<>();
        String profile = "balanced";
        String listener = "";
        String firewall = "rate_limit:\n    enabled: false\n";
        String clientIp = "trusted_proxies: [127.0.0.1]\n";
        String route = "";
        String topLevel = "";
        String hostOfRoute = "\"*\"";
        int listenerPort;
        String pathPrefix = "/";
        String responseTimeout = "5s";
        String tlsHosts = "";
        boolean tls;

        Config(Path dir) {
            this.dir = dir;
        }

        Config backends(int... ports) {
            for (int port : ports) {
                backendPorts.add(port);
            }
            return this;
        }

        Config listener(String yaml) {
            listener = yaml;
            return this;
        }

        Config firewall(String yaml) {
            firewall = yaml;
            return this;
        }

        Config route(String yaml) {
            route = yaml;
            return this;
        }

        Config topLevel(String yaml) {
            topLevel = yaml;
            return this;
        }

        Config profile(String name) {
            profile = name;
            return this;
        }

        Config host(String host) {
            hostOfRoute = host;
            return this;
        }

        Config listenerPort(int port) {
            listenerPort = port;
            return this;
        }

        Config pathPrefix(String prefix) {
            pathPrefix = prefix;
            return this;
        }

        Config responseTimeout(String timeout) {
            responseTimeout = timeout;
            return this;
        }

        Config tls(String tlsEntries) {
            tls = true;
            tlsHosts = tlsEntries;
            return this;
        }

        Path logFile() {
            return dir.resolve("logs").resolve("aegis.log");
        }

        String yaml() {
            return "profile: " + profile + "\n"
                    + "listener:\n  bind: 127.0.0.1\n  port: " + listenerPort + "\n  tls: " + tls + "\n" + indent(listener, 2)
                    + "admin:\n  enabled: true\n  bind: 127.0.0.1\n  port: 0\n"
                    + "log:\n  directory: " + dir.resolve("logs") + "\n  logged_query_params: [page]\n"
                    + "client_ip:\n" + indent(clientIp, 2)
                    + "firewall:\n" + indent(firewall, 2)
                    + "rule_sets:\n"
                    + "  - name: test\n    file: " + TEST_RULES + "\n    mode: block\n"
                    + "  - name: monitor\n    file: " + MONITOR_RULES + "\n    mode: monitor\n"
                    + topLevel
                    + tlsHosts
                    + "routes:\n  - name: web\n    host: " + hostOfRoute + "\n    path_prefix: " + pathPrefix + "\n"
                    + "    backends: [" + String.join(", ", backendPorts.stream().map(p -> "127.0.0.1:" + p).toList()) + "]\n"
                    + "    health:\n      failures_to_eject: 2\n      ejection_time: 30s\n"
                    + "    connect_timeout: 1s\n    response_timeout: " + responseTimeout + "\n"
                    + indent(route, 4);
        }

        TestProxy start() {
            return new TestProxy(this, AegisServer.start(ConfigLoader.parse(yaml())));
        }

        private static String indent(String yaml, int spaces) {
            return yaml.isEmpty() ? "" : yaml.indent(spaces);
        }
    }

    private final Config config;
    private final AegisServer server;
    private final HttpClient http = HttpClient.newHttpClient();

    private TestProxy(Config config, AegisServer server) {
        this.config = config;
        this.server = server;
    }

    static Config config(Path dir) {
        return new Config(dir);
    }

    int port() {
        return server.port();
    }

    AegisServer server() {
        return server;
    }

    /** The admin endpoint's body for {@code path}. */
    String admin(String path) throws IOException, InterruptedException {
        return adminResponse(path).body();
    }

    HttpResponse<String> adminResponse(String path) throws IOException, InterruptedException {
        return http.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + server.adminPort() + path)).build(),
                HttpResponse.BodyHandlers.ofString());
    }

    /** Every logged event of the type, oldest first. */
    List<JsonNode> events(String type) throws IOException {
        List<JsonNode> found = new ArrayList<>();
        if (!Files.exists(config.logFile())) {
            return found;
        }
        for (String line : Files.readAllLines(config.logFile())) {
            JsonNode event = JSON.readTree(line);
            if (event.get("type").asText().equals(type)) {
                found.add(event);
            }
        }
        return found;
    }

    /**
     * Waits until the log holds a matching event, because the log is written by its own thread.
     *
     * @throws AssertionError if none appears within five seconds
     */
    JsonNode awaitEvent(String type, Predicate<JsonNode> matching) throws Exception {
        long deadline = System.nanoTime() + 5_000_000_000L;
        while (System.nanoTime() < deadline) {
            for (JsonNode event : events(type)) {
                if (matching.test(event)) {
                    return event;
                }
            }
            Thread.sleep(10);
        }
        throw new AssertionError("No " + type + " event matched within 5 s; log holds " + events(type));
    }

    /** The {@code request} event with this request ID. */
    JsonNode requestEvent(String requestId) throws Exception {
        return awaitEvent("request", e -> e.get("request_id").asText().equals(requestId));
    }

    @Override
    public void close() {
        server.close();
    }
}
