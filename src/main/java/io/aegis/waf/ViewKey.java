package io.aegis.waf;

import io.aegis.http.RuleBuffer;
import io.aegis.rules.Transform;
import java.util.List;

/**
 * What a condition inspects: a request buffer after an ordered list of transforms. Conditions
 * with equal keys share one computed view and one prefilter.
 */
record ViewKey(RuleBuffer buffer, List<Transform> transforms) {
}
