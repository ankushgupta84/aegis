package io.aegis.waf;

/** One condition of a rule, compiled: the view it inspects is resolved to an id. */
sealed interface Step permits ContentStep, PcreStep {

    int viewId();

    boolean negated();
}
