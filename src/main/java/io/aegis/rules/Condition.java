package io.aegis.rules;

import io.aegis.http.RuleBuffer;
import java.util.List;

/** One test a rule applies to one buffer. A rule matches when all of its conditions hold. */
public sealed interface Condition permits ContentMatch, PcreMatch {

    RuleBuffer buffer();

    /** Transforms applied to the buffer, in order, before this condition looks at it. */
    List<Transform> transforms();

    /** True when the condition holds only if the pattern is absent ({@code content:!"..."}). */
    boolean negated();
}
