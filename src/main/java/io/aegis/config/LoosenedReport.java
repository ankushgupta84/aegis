package io.aegis.config;

import io.aegis.net.Cidr;
import io.aegis.policy.AegisConfig;
import io.aegis.policy.Exemption;
import io.aegis.policy.RoutePolicy;
import io.aegis.policy.RuleMode;
import io.aegis.policy.RuleSetSource;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * The "Loosened" section of an explanation: every exemption with its reason and owner, and every
 * rule or rule set a route runs below {@code block}. Tenet 2: loosening shows up in one list.
 */
final class LoosenedReport {
    private static final ValueType<RuleMode> MODE = ValueTypes.enumeration(RuleMode.class);

    private LoosenedReport() {
    }

    static String of(AegisConfig config) {
        List<String> lines = new ArrayList<>();
        config.firewall().exemptions().forEach(exemption -> lines.add(describe(exemption)));
        config.routes().forEach(route -> lines.addAll(belowBlock(config, route)));
        if (lines.isEmpty()) {
            lines.add("nothing");
        }
        return "Loosened\n" + lines.stream().map(line -> "  " + line).collect(Collectors.joining("\n"));
    }

    private static String describe(Exemption exemption) {
        String sources = exemption.sources().stream().map(Cidr::toString).collect(Collectors.joining(", "));
        String skips = exemption.skips().stream().map(ValueTypes.SKIP::show).collect(Collectors.joining(", "));
        return "exemption " + exemption.name() + ": clients " + sources + " skip " + skips
                + ". Reason: " + exemption.reason() + ". Owner: " + exemption.owner() + ".";
    }

    /** Rule sets in declaration order and rules by sid: the policy's maps have no order of their own. */
    private static List<String> belowBlock(AegisConfig config, RoutePolicy route) {
        List<String> lines = new ArrayList<>();
        for (RuleSetSource source : config.ruleSets()) {
            RuleMode mode = route.waf().ruleSetModes().get(source.name());
            if (mode != RuleMode.BLOCK) {
                lines.add("route " + route.name() + " runs rule set " + source.name() + " in " + MODE.show(mode) + " mode");
            }
        }
        route.waf().sidModes().entrySet().stream()
                .filter(rule -> rule.getValue() != RuleMode.BLOCK)
                .sorted(Map.Entry.comparingByKey())
                .forEach(rule -> lines.add(
                        "route " + route.name() + " runs rule " + rule.getKey() + " in " + MODE.show(rule.getValue()) + " mode"));
        return lines;
    }
}
