package io.aegis.policy;

import java.time.Duration;

/**
 * The WAF's tunable behavior for one route, fully resolved: no knob is left to a default at
 * request time.
 *
 * @param blockThreshold     a request whose block-mode hits total this score or more is blocked
 * @param bodyScanLimitBytes how much of a request body is inspected
 * @param onBodyOverLimit    what to do when the body is longer than the scan limit
 * @param inspectionBudget   the longest inspection of one request may take
 * @param onBudgetExceeded   what to do when inspection runs out of budget
 * @param onEngineError      what to do when the rule engine fails
 */
public record WafKnobs(
        int blockThreshold,
        int bodyScanLimitBytes,
        FailAction onBodyOverLimit,
        Duration inspectionBudget,
        FailAction onBudgetExceeded,
        FailAction onEngineError) {
}
