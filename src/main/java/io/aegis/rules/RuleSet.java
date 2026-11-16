package io.aegis.rules;

import java.util.List;

/** A named, imported rule file: every rule it held, active or not. */
public record RuleSet(String name, List<ClassifiedRule> rules) {

    public RuleSet {
        rules = List.copyOf(rules);
    }

    public List<SuricataRule> activeRules() {
        return rules.stream()
                .filter(rule -> rule.status() == RuleStatus.ACTIVE)
                .map(ClassifiedRule::rule)
                .toList();
    }

    public long count(RuleStatus status) {
        return rules.stream().filter(rule -> rule.status() == status).count();
    }
}
