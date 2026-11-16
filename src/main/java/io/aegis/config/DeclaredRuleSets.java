package io.aegis.config;

import io.aegis.policy.RuleMode;
import io.aegis.policy.RuleSetSource;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** The rule sets declared under {@code rule_sets}: the only names routes and exemptions may refer to. */
record DeclaredRuleSets(List<RuleSetSource> sources) {

    boolean contains(String name) {
        return sources.stream().anyMatch(source -> source.name().equals(name));
    }

    /** Each declared rule set with the mode it runs in unless a route says otherwise. */
    Map<String, RuleMode> declaredModes() {
        Map<String, RuleMode> modes = new LinkedHashMap<>();
        sources.forEach(source -> modes.put(source.name(), source.defaultMode()));
        return modes;
    }

    String notDeclared(String name) {
        String declared = sources.isEmpty()
                ? "No rule sets are declared under rule_sets."
                : "Declared rule sets: " + String.join(", ", declaredModes().keySet()) + ".";
        return "'" + name + "' is not a declared rule set. " + declared;
    }
}
