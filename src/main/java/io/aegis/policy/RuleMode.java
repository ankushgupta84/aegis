package io.aegis.policy;

/** How a rule or rule set takes part in a route's decision. */
public enum RuleMode {

    /** A match adds the rule's score; a total at the threshold blocks. */
    BLOCK,

    /** A match is logged and counted but adds no score. Imported rule sets start here. */
    MONITOR,

    /** The rule is not evaluated for this route. */
    DISABLED
}
