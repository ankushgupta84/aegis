package io.aegis.rules;

import java.util.Objects;

/**
 * One line of an imported rule file and what became of it.
 *
 * @param sid    the rule's sid, or 0 when the line could not be parsed far enough to find one
 * @param reason why the rule is not active, in plain language; empty for an active rule
 * @param rule   the parsed rule; null unless {@code status} is {@link RuleStatus#ACTIVE}
 * @param raw    the rule text exactly as imported
 */
public record ClassifiedRule(int sid, int rev, RuleStatus status, String reason, SuricataRule rule, String raw) {

    public ClassifiedRule {
        Objects.requireNonNull(status);
        Objects.requireNonNull(reason);
        Objects.requireNonNull(raw);
        if ((status == RuleStatus.ACTIVE) != (rule != null)) {
            throw new IllegalArgumentException("Exactly the active rules carry a parsed rule (sid " + sid + ")");
        }
    }

    public static ClassifiedRule active(SuricataRule rule) {
        return new ClassifiedRule(rule.sid(), rule.rev(), RuleStatus.ACTIVE, "", rule, rule.raw());
    }

    public static ClassifiedRule skipped(int sid, int rev, RuleStatus status, String reason, String raw) {
        return new ClassifiedRule(sid, rev, status, reason, null, raw);
    }
}
