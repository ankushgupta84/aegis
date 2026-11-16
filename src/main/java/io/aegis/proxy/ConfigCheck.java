package io.aegis.proxy;

import io.aegis.policy.AegisConfig;
import io.aegis.rules.ClassifiedRule;
import io.aegis.rules.RuleSet;
import io.aegis.rules.RuleStatus;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * The report behind {@code aegis check}: how many rules of each rule set Aegis will apply and why
 * it skips the rest. Opens no sockets, so it is safe to run on a machine that serves traffic.
 */
public final class ConfigCheck {

    private static final int TOP_REASONS = 10;

    private ConfigCheck() {
    }

    /** @throws StartupException if a rule file cannot be read */
    public static String report(AegisConfig config) {
        StringBuilder text = new StringBuilder();
        for (RuleSet set : RuleSetLoader.load(config.ruleSets())) {
            text.append("rule set ").append(set.name()).append(": ")
                    .append(set.count(RuleStatus.ACTIVE)).append(" active, ")
                    .append(set.count(RuleStatus.NOT_APPLICABLE)).append(" not applicable, ")
                    .append(set.count(RuleStatus.UNSUPPORTED)).append(" unsupported\n");
            skippedReasons(set).forEach(reason -> text.append("  ")
                    .append(reason.getValue()).append(" x ").append(reason.getKey()).append('\n'));
        }
        return text.toString();
    }

    private static List<Map.Entry<String, Long>> skippedReasons(RuleSet set) {
        return set.rules().stream()
                .filter(rule -> rule.status() != RuleStatus.ACTIVE)
                .collect(Collectors.groupingBy(ClassifiedRule::reason, Collectors.counting()))
                .entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue(Comparator.reverseOrder())
                        .thenComparing(Map.Entry.comparingByKey()))
                .limit(TOP_REASONS)
                .toList();
    }
}
