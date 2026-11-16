package io.aegis.rules;

/** What Aegis does with an imported rule. Every rule gets exactly one status, and all are counted. */
public enum RuleStatus {

    /** Evaluated in full. */
    ACTIVE,

    /** Written for traffic Aegis never sees, such as DNS or SMB. */
    NOT_APPLICABLE,

    /**
     * Uses something Aegis does not implement. The rule is skipped whole, never partly applied:
     * dropping one condition would widen the match.
     */
    UNSUPPORTED
}
