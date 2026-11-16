package io.aegis.loadtest;

import java.nio.file.Path;
import java.time.Duration;
import java.util.Optional;
import java.util.Set;

/**
 * Settings of a {@link DummyBackend}.
 *
 * @param port  listening port; 0 picks an ephemeral one
 * @param name  identity echoed in the body and the {@code X-Backend} header
 * @param delay time to wait before answering, to simulate a slow origin
 * @param tls   certificate chain and key to serve TLS with, or empty for plain HTTP
 */
public record BackendOptions(int port, String name, Duration delay, Optional<TlsFiles> tls) {

    /** PEM files a backend serves TLS with. */
    public record TlsFiles(Path certificate, Path key) {
    }

    static final String HELP = """
            Usage: DummyBackend --port N --name NAME [--delay-ms N] [--tls-cert FILE --tls-key FILE]

              --port N         listening port, 0 for an ephemeral one (default 0)
              --name NAME      identity returned in the body and the X-Backend header (required)
              --delay-ms N     wait N milliseconds before every answer (default 0)
              --tls-cert FILE  PEM certificate chain; serves TLS when given with --tls-key
              --tls-key FILE   PEM PKCS#8 private key
            """;

    private static final Set<String> FLAGS = Set.of("--port", "--name", "--delay-ms", "--tls-cert", "--tls-key");

    public BackendOptions {
        if (port < 0 || port > 65535) {
            throw new UsageException("--port must be between 0 and 65535");
        }
        if (name.isBlank()) {
            throw new UsageException("--name must not be blank");
        }
        if (delay.isNegative()) {
            throw new UsageException("--delay-ms must not be negative");
        }
    }

    public static BackendOptions plain(String name) {
        return new BackendOptions(0, name, Duration.ZERO, Optional.empty());
    }

    public BackendOptions withDelay(Duration newDelay) {
        return new BackendOptions(port, name, newDelay, tls);
    }

    public BackendOptions withTls(TlsFiles files) {
        return new BackendOptions(port, name, delay, Optional.of(files));
    }

    static BackendOptions parse(String[] args) {
        FlagArguments flags = new FlagArguments(args, FLAGS);
        Optional<String> cert = flags.get("--tls-cert");
        Optional<String> key = flags.get("--tls-key");
        if (cert.isPresent() != key.isPresent()) {
            throw new UsageException("--tls-cert and --tls-key go together");
        }
        Optional<TlsFiles> tls = cert.map(c -> new TlsFiles(Path.of(c), Path.of(key.get())));
        return new BackendOptions(
                (int) Units.parseLong("--port", flags.get("--port", "0")),
                flags.require("--name"),
                Duration.ofMillis(Units.parseLong("--delay-ms", flags.get("--delay-ms", "0"))),
                tls);
    }
}
