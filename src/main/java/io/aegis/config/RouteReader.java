package io.aegis.config;

import io.aegis.policy.BackendAddress;
import io.aegis.policy.Exemption;
import io.aegis.policy.HealthKnobs;
import io.aegis.policy.RoutePolicy;
import io.aegis.policy.RuleMode;
import io.aegis.policy.UpstreamPolicy;
import io.aegis.policy.UpstreamTls;
import io.aegis.policy.WafKnobs;
import io.aegis.policy.WafPolicy;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Reads one entry of {@code routes} into a fully resolved {@link RoutePolicy}. */
final class RouteReader {
    private static final ValueType<RuleMode> MODE = ValueTypes.enumeration(RuleMode.class);
    private static final ValueType<Integer> POSITIVE = ValueTypes.integer(1, Integer.MAX_VALUE);
    private static final String DECLARED = "rule_sets declaration";

    private final DeclaredRuleSets ruleSets;
    private final WafResolver waf;
    private final List<Exemption> exemptions;
    private final Problems problems;
    private final Ledger ledger;

    RouteReader(DeclaredRuleSets ruleSets, WafResolver waf, List<Exemption> exemptions,
                Problems problems, Ledger ledger) {
        this.ruleSets = ruleSets;
        this.waf = waf;
        this.exemptions = exemptions;
        this.problems = problems;
        this.ledger = ledger;
    }

    Optional<RoutePolicy> read(Section route) {
        int before = problems.count();
        Optional<String> name = route.required("name", ValueTypes.TEXT);
        String host = route.value("host", ValueTypes.HOSTNAME, "*");
        String pathPrefix = route.value("path_prefix", ValueTypes.PATH_PREFIX, "/");
        UpstreamPolicy upstream = upstream(route);
        WafPolicy wafPolicy = wafPolicy(route, name.orElse(route.label()));
        if (problems.count() > before) {
            return Optional.empty();
        }
        return Optional.of(new RoutePolicy(name.get(), host, pathPrefix, wafPolicy, upstream));
    }

    private UpstreamPolicy upstream(Section route) {
        List<BackendAddress> backends = route.requiredList("backends", ValueTypes.BACKEND).orElse(List.of());
        HealthKnobs health = health(route.child("health"));
        Duration connectTimeout = route.value("connect_timeout", ValueTypes.DURATION, Duration.ofSeconds(2));
        Duration responseTimeout = route.value("response_timeout", ValueTypes.DURATION, Duration.ofSeconds(30));
        return new UpstreamPolicy(backends, health, connectTimeout, responseTimeout,
                upstreamTls(route.child("upstream_tls")));
    }

    private HealthKnobs health(Section health) {
        return new HealthKnobs(
                health.value("failures_to_eject", POSITIVE, 3),
                health.value("ejection_time", ValueTypes.DURATION, Duration.ofSeconds(5)),
                health.value("count_server_errors", ValueTypes.BOOLEAN, false));
    }

    private UpstreamTls upstreamTls(Section tls) {
        boolean enabled = tls.value("enabled", ValueTypes.BOOLEAN, false);
        Optional<Path> trustedCa = tls.optional("trusted_ca", ValueTypes.FILE);
        Optional<String> pinned = tls.optional("pinned_sha256", ValueTypes.SHA256);
        if (!enabled && (trustedCa.isPresent() || pinned.isPresent())) {
            problems.add(tls.whereOf("enabled") + " is false, so trusted_ca and pinned_sha256 would be ignored. "
                    + "Set enabled: true or remove them.");
        }
        return new UpstreamTls(enabled, trustedCa, pinned);
    }

    private WafPolicy wafPolicy(Section route, String name) {
        WafKnobs knobs = waf.resolve(route.label(), name, WafOverrides.read(route.child("waf")));
        Map<String, RuleMode> ruleSetModes = ruleSetModes(route, name);
        Map<Integer, RuleMode> sidModes = new LinkedHashMap<>();
        Map<Integer, Integer> sidScores = new LinkedHashMap<>();
        for (Section rule : route.children("rules", "sid")) {
            Optional<Integer> sid = rule.required("sid", POSITIVE);
            Optional<RuleMode> mode = rule.quiet("mode", MODE);
            Optional<Integer> score = rule.quiet("score", POSITIVE);
            if (sid.isPresent()) {
                mode.ifPresent(m -> sidModes.put(sid.get(), m));
                score.ifPresent(s -> sidScores.put(sid.get(), s));
                mode.ifPresent(m -> ledger.record(rule.label() + ".mode", MODE.show(m), "route " + name));
                score.ifPresent(s -> ledger.record(rule.label() + ".score", POSITIVE.show(s), "route " + name));
            }
        }
        return new WafPolicy(knobs, ruleSetModes, sidModes, sidScores, exemptions);
    }

    private Map<String, RuleMode> ruleSetModes(Section route, String name) {
        Map<String, RuleMode> overrides = route.map("rule_sets", MODE);
        overrides.keySet().stream()
                .filter(set -> !ruleSets.contains(set))
                .forEach(set -> problems.add(route.whereOf("rule_sets") + "." + set + ": " + ruleSets.notDeclared(set)));
        Map<String, RuleMode> modes = ruleSets.declaredModes();
        modes.replaceAll((set, declared) -> overrides.getOrDefault(set, declared));
        modes.forEach((set, mode) -> ledger.record(route.label() + ".rule_sets." + set, MODE.show(mode),
                overrides.containsKey(set) ? "route " + name : DECLARED));
        return modes;
    }
}
