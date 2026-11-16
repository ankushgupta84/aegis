package io.aegis.policy;

/**
 * One thing an exemption skips. An exemption skips only what it names; there is no blanket bypass.
 *
 * @param target the rule set name or the sid; empty for kinds that skip a whole stage
 */
public record Skip(Kind kind, String target) {

    public enum Kind {
        /** The per-client rate limit. */
        RATE_LIMIT,
        /** The whole WAF stage. */
        WAF,
        /** One rule set, by name. */
        RULE_SET,
        /** One rule, by sid. */
        SID
    }

    public static Skip rateLimit() {
        return new Skip(Kind.RATE_LIMIT, "");
    }

    public static Skip waf() {
        return new Skip(Kind.WAF, "");
    }

    public static Skip ruleSet(String name) {
        return new Skip(Kind.RULE_SET, name);
    }

    public static Skip sid(int sid) {
        return new Skip(Kind.SID, Integer.toString(sid));
    }
}
