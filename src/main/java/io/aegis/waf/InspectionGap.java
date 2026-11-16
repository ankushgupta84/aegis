package io.aegis.waf;

/**
 * A way inspection fell short of the whole request. A gap is never silent: each one is logged and
 * counted, and policy decides whether it blocks.
 */
public enum InspectionGap {

    /** The body was longer than the scan limit, so only its prefix was inspected. */
    BODY_OVER_SCAN_LIMIT,

    /** Inspection ran out of its time budget before every candidate rule was confirmed. */
    TIME_BUDGET_EXCEEDED,

    /** The engine threw. No rule result can be trusted for this request. */
    ENGINE_ERROR
}
