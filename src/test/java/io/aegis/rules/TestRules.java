package io.aegis.rules;

import java.io.IOException;
import java.io.StringReader;

/** Helpers that turn a line of rule text into its classification. */
final class TestRules {

    private TestRules() {
    }

    /** Classifies a whole file given as text; the result holds one entry per rule. */
    static RuleSet parse(String fileText) {
        try {
            return SuricataRuleParser.parse("test", new StringReader(fileText));
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }

    /** Classifies one rule written in full. */
    static ClassifiedRule classify(String rule) {
        RuleSet set = parse(rule);
        if (set.rules().size() != 1) {
            throw new AssertionError("expected one rule, got " + set.rules().size());
        }
        return set.rules().get(0);
    }

    /** Classifies an HTTP rule given only its options, which must include a sid. */
    static ClassifiedRule http(String options) {
        return classify("alert http any any -> any any (" + options + ")");
    }

    /** The parsed rule of an options string that must classify as active. */
    static SuricataRule active(String options) {
        ClassifiedRule result = http(options);
        if (result.status() != RuleStatus.ACTIVE) {
            throw new AssertionError("expected ACTIVE but was " + result.status() + ": " + result.reason());
        }
        return result.rule();
    }
}
