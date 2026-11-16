package io.aegis.loadtest;

import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Optional;
import java.util.Set;

/**
 * Everything a load run is told on the command line, validated.
 *
 * @param url               target origin; http or https, host and optional port, no path
 * @param rate              requests per second, held steady regardless of response time
 * @param duration          length of the measured phase
 * @param warmup            length of the unrecorded phase before it
 * @param connections       keep-alive connections shared by the requests
 * @param newConnectionShare fraction of requests that use a fresh connection, closed afterwards
 * @param postShare         fraction of requests that are POSTs
 * @param bodyMinBytes      smallest POST body
 * @param bodyMaxBytes      largest POST body
 * @param attackShare       fraction of requests that carry an attack payload
 * @param hostHeader        value of the Host header
 * @param tlsTrust          PEM file of certificates to trust for https, or empty for the JVM default
 * @param label             free text identifying the run in the report
 * @param seed              seed of the request mix, so a run can be repeated
 * @param timeout           per-request limit, measured from the intended send time
 * @param jsonFile          where to write the report as JSON, if anywhere
 */
public record LoadTestOptions(
        URI url,
        long rate,
        Duration duration,
        Duration warmup,
        int connections,
        double newConnectionShare,
        double postShare,
        int bodyMinBytes,
        int bodyMaxBytes,
        double attackShare,
        String hostHeader,
        Optional<Path> tlsTrust,
        String label,
        long seed,
        Duration timeout,
        Optional<Path> jsonFile) {

    static final String HELP = """
            Usage: LoadTester --url URL [options]

            Open-loop load generator: requests leave on a fixed schedule whatever the server does,
            and latency is measured from each request's intended send time.

              --url URL                  http(s)://host[:port] target (required)
              --rate N                   requests per second (default 5000)
              --duration D               measured phase, e.g. 600s (default 600s)
              --warmup D                 unrecorded phase before it (default 120s)
              --connections N            keep-alive connections (default 64)
              --new-connection-share F   fraction of requests on a fresh connection, TLS handshake
                                         included, closed afterwards (default 0.05)
              --post-share F             fraction of POST requests (default 0.30)
              --body-min S               smallest POST body, e.g. 1KB (default 1KB)
              --body-max S               largest POST body, e.g. 64KB (default 64KB)
              --attack-share F           fraction of requests carrying an attack payload (default 0.01)
              --host-header NAME         Host header (default: host and port of --url)
              --tls-trust FILE           PEM CA bundle or server certificate to trust for https
                                         (default: the JVM trust store)
              --timeout D                per-request limit from intended send time (default 5s)
              --label TEXT               name of the run, printed in the report
              --seed N                   seed of the request mix (default: random, printed in the report)
              --json FILE                also write the report as JSON
              --help                     this text

            Durations take ms, s, m or h. Sizes take B, KB or MB.
            """;

    private static final Set<String> FLAGS = Set.of(
            "--url", "--rate", "--duration", "--warmup", "--connections", "--new-connection-share",
            "--post-share", "--body-min", "--body-max", "--attack-share", "--host-header",
            "--tls-trust", "--timeout", "--label", "--seed", "--json");

    public LoadTestOptions {
        requireOrigin(url);
        if (duration.isZero()) {
            throw new UsageException("--duration must be positive");
        }
        if (timeout.isZero()) {
            throw new UsageException("--timeout must be positive");
        }
        if (bodyMinBytes > bodyMaxBytes) {
            throw new UsageException("--body-min must not exceed --body-max");
        }
        if (hostHeader.isBlank()) {
            throw new UsageException("--host-header must not be blank");
        }
    }

    boolean https() {
        return url.getScheme().equals("https");
    }

    int port() {
        return url.getPort() != -1 ? url.getPort() : https() ? 443 : 80;
    }

    static LoadTestOptions parse(String[] args) {
        FlagArguments flags = new FlagArguments(args, FLAGS);
        URI url = parseUrl(flags.require("--url"));
        return new LoadTestOptions(
                url,
                Units.parsePositiveLong("--rate", flags.get("--rate", "5000")),
                Units.parseDuration("--duration", flags.get("--duration", "600s")),
                Units.parseDuration("--warmup", flags.get("--warmup", "120s")),
                (int) Units.parsePositiveLong("--connections", flags.get("--connections", "64")),
                Units.parseShare("--new-connection-share", flags.get("--new-connection-share", "0.05")),
                Units.parseShare("--post-share", flags.get("--post-share", "0.30")),
                Units.parseSizeBytes("--body-min", flags.get("--body-min", "1KB")),
                Units.parseSizeBytes("--body-max", flags.get("--body-max", "64KB")),
                Units.parseShare("--attack-share", flags.get("--attack-share", "0.01")),
                flags.get("--host-header").orElse(url.getAuthority()),
                flags.get("--tls-trust").map(Path::of),
                flags.get("--label", ""),
                flags.get("--seed").map(s -> Units.parseLong("--seed", s)).orElseGet(System::nanoTime),
                Units.parseDuration("--timeout", flags.get("--timeout", "5s")),
                flags.get("--json").map(Path::of));
    }

    private static URI parseUrl(String text) {
        try {
            return URI.create(text);
        } catch (IllegalArgumentException e) {
            throw new UsageException("--url: '" + text + "' is not a valid URL");
        }
    }

    private static void requireOrigin(URI url) {
        String scheme = url.getScheme();
        if (!"http".equals(scheme) && !"https".equals(scheme)) {
            throw new UsageException("--url must start with http:// or https://");
        }
        if (url.getHost() == null) {
            throw new UsageException("--url needs a host");
        }
        String path = url.getRawPath();
        if (url.getRawQuery() != null || !(path == null || path.isEmpty() || path.equals("/"))) {
            throw new UsageException("--url takes only scheme, host and port; the request mix picks the paths");
        }
    }
}
