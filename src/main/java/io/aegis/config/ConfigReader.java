package io.aegis.config;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import io.aegis.net.Cidr;
import io.aegis.policy.Admin;
import io.aegis.policy.AegisConfig;
import io.aegis.policy.ClientIpPolicy;
import io.aegis.policy.Exemption;
import io.aegis.policy.FirewallPolicy;
import io.aegis.policy.Listener;
import io.aegis.policy.LogSettings;
import io.aegis.policy.RateLimit;
import io.aegis.policy.RoutePolicy;
import io.aegis.policy.RuleMode;
import io.aegis.policy.RuleSetSource;
import io.aegis.policy.TlsHost;
import io.aegis.policy.WafKnobs;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

/**
 * Turns YAML text into a validated {@link AegisConfig} and the ledger of where each value came
 * from. Defaults for optional keys are written here, next to the key they belong to.
 */
final class ConfigReader {
    private static final YAMLMapper YAML = YAMLMapper.builder()
            .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .build();
    private static final ValueType<Integer> PORT = ValueTypes.integer(1, 65535);
    /** Port 0 asks the operating system for a free port, which tests rely on. */
    private static final ValueType<Integer> LISTEN_PORT = ValueTypes.integer(0, 65535);
    private static final ValueType<Integer> POSITIVE = ValueTypes.integer(1, Integer.MAX_VALUE);
    /** Stands in for a missing or misspelled profile so the rest of the file is still checked. */
    private static final String PROFILE_FOR_CHECKING = "balanced";

    private static final String NO_TLS_ENTRY = "listener.tls is true but there is no 'tls' entry to say which "
            + "certificate to present. Add a tls entry with a hostname and a certificate, or set listener.tls to false.";

    private final Section root;
    private final Problems problems;
    private final Ledger ledger;

    private ConfigReader(Section root, Problems problems, Ledger ledger) {
        this.root = root;
        this.problems = problems;
        this.ledger = ledger;
    }

    static Resolution read(String yaml) {
        Problems problems = new Problems();
        Ledger ledger = new Ledger();
        Section root = Section.root(parse(yaml), problems, ledger);
        AegisConfig config = new ConfigReader(root, problems, ledger).config();
        root.rejectUnknownKeys();
        problems.throwIfAny();
        return new Resolution(config, ledger);
    }

    private static JsonNode parse(String yaml) {
        try {
            JsonNode tree = YAML.readTree(yaml);
            if (tree == null || tree.isMissingNode() || tree.isNull()) {
                throw new ConfigException(List.of("The file is empty. Start with 'profile: balanced' and add a listener, "
                        + "a tls entry, and at least one route."));
            }
            return tree;
        } catch (JsonProcessingException e) {
            int line = e.getLocation() == null ? 0 : e.getLocation().getLineNr();
            throw new ConfigException(List.of("The file is not valid YAML (line " + line + "): " + e.getOriginalMessage()));
        }
    }

    private AegisConfig config() {
        String profile = root.required("profile", ValueTypes.choice(Profiles.names())).orElse(PROFILE_FOR_CHECKING);
        DeclaredRuleSets ruleSets = new DeclaredRuleSets(ruleSetSources());
        WafOverrides globalWaf = WafOverrides.read(root.child("waf"));
        List<Exemption> exemptions = new ExemptionReader(ruleSets, problems).read(root);
        Listener listener = listener();
        Admin admin = admin();
        LogSettings log = log();
        ClientIpPolicy clientIp = new ClientIpPolicy(root.child("client_ip").list("trusted_proxies", ValueTypes.CIDR, List.of()));
        FirewallPolicy firewall = firewall(exemptions);
        int beforeTls = problems.count();
        List<TlsHost> tlsHosts = new TlsReader(problems, ledger).read(root);
        if (listener.tls() && tlsHosts.isEmpty() && problems.count() == beforeTls) {
            problems.add(NO_TLS_ENTRY);
        }
        WafKnobs profileKnobs = Profiles.wafKnobs(profile).orElseThrow();
        RouteReader routeReader = new RouteReader(ruleSets,
                new WafResolver(profile, profileKnobs, globalWaf, ledger), exemptions, problems, ledger);
        return new AegisConfig(profile, listener, admin, log, clientIp, firewall,
                ruleSets.sources(), tlsHosts, routes(routeReader));
    }

    private List<RuleSetSource> ruleSetSources() {
        return root.children("rule_sets", "name").stream()
                .map(this::ruleSetSource)
                .flatMap(Optional::stream)
                .toList();
    }

    private Optional<RuleSetSource> ruleSetSource(Section section) {
        int before = problems.count();
        Optional<String> name = section.required("name", ValueTypes.TEXT);
        Optional<Path> file = section.required("file", ValueTypes.FILE);
        Optional<RuleMode> mode = section.required("mode", ValueTypes.enumeration(RuleMode.class),
                "Write block, monitor, or disabled; imported rule sets should start in monitor.");
        if (problems.count() > before) {
            return Optional.empty();
        }
        return Optional.of(new RuleSetSource(name.get(), file.get(), mode.get()));
    }

    private Listener listener() {
        Section s = root.child("listener");
        return new Listener(
                s.value("bind", ValueTypes.TEXT, "0.0.0.0"),
                s.value("port", LISTEN_PORT, 8443),
                s.value("tls", ValueTypes.BOOLEAN, true),
                s.value("max_header_bytes", ValueTypes.BYTES_AS_INT, 16 * 1024),
                s.value("max_body_bytes", ValueTypes.BYTES_AS_INT, 10 * 1024 * 1024),
                s.value("header_timeout", ValueTypes.DURATION, Duration.ofSeconds(10)),
                s.value("idle_timeout", ValueTypes.DURATION, Duration.ofSeconds(60)),
                s.value("drain_timeout", ValueTypes.DURATION, Duration.ofSeconds(30)));
    }

    private Admin admin() {
        Section s = root.child("admin");
        return new Admin(
                s.value("enabled", ValueTypes.BOOLEAN, true),
                s.value("bind", ValueTypes.TEXT, "127.0.0.1"),
                s.value("port", LISTEN_PORT, 9090));
    }

    private LogSettings log() {
        Section s = root.child("log");
        return new LogSettings(
                s.value("directory", ValueTypes.FILE, Path.of("logs")),
                s.value("rotate_at", ValueTypes.BYTES, 100L * 1024 * 1024),
                s.value("keep_files", POSITIVE, 10),
                s.list("logged_query_params", ValueTypes.TEXT, List.of("page", "limit", "sort")));
    }

    private FirewallPolicy firewall(List<Exemption> exemptions) {
        Section s = root.child("firewall");
        List<Cidr> allow = s.list("allow", ValueTypes.CIDR, List.of());
        List<Cidr> deny = s.list("deny", ValueTypes.CIDR, List.of());
        return new FirewallPolicy(allow, deny, rateLimit(s.child("rate_limit")), exemptions);
    }

    private RateLimit rateLimit(Section s) {
        return new RateLimit(
                s.value("enabled", ValueTypes.BOOLEAN, true),
                s.value("requests_per_second", ValueTypes.POSITIVE_NUMBER, 100.0),
                s.value("burst", POSITIVE, 50),
                s.value("ipv4_prefix", ValueTypes.integer(0, 32), 32),
                s.value("ipv6_prefix", ValueTypes.integer(0, 128), 64),
                s.value("max_tracked_clients", POSITIVE, 100_000));
    }

    private List<RoutePolicy> routes(RouteReader routeReader) {
        int before = problems.count();
        List<Section> sections = root.children("routes", "name");
        if (sections.isEmpty() && problems.count() == before) {
            problems.add("routes is required: add at least one route with a name and backends.");
        }
        return sections.stream().map(routeReader::read).flatMap(Optional::stream).toList();
    }
}
