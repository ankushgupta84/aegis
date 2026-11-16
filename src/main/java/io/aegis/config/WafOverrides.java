package io.aegis.config;

import io.aegis.policy.FailAction;
import java.time.Duration;
import java.util.Optional;

/**
 * The WAF knobs one scope (the global section or one route) sets explicitly. Anything left empty
 * is decided by a wider scope.
 */
record WafOverrides(
        Optional<Integer> blockThreshold,
        Optional<Integer> bodyScanLimitBytes,
        Optional<FailAction> onBodyOverLimit,
        Optional<Duration> inspectionBudget,
        Optional<FailAction> onBudgetExceeded,
        Optional<FailAction> onEngineError) {

    private static final ValueType<Integer> THRESHOLD = ValueTypes.integer(1, Integer.MAX_VALUE);
    private static final ValueType<FailAction> FAIL_ACTION = ValueTypes.enumeration(FailAction.class);

    static WafOverrides read(Section waf) {
        return new WafOverrides(
                waf.quiet("block_threshold", THRESHOLD),
                waf.quiet("body_scan_limit", ValueTypes.BYTES_AS_INT),
                waf.quiet("on_body_over_limit", FAIL_ACTION),
                waf.quiet("inspection_budget", ValueTypes.DURATION),
                waf.quiet("on_budget_exceeded", FAIL_ACTION),
                waf.quiet("on_engine_error", FAIL_ACTION));
    }
}
