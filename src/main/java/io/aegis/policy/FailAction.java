package io.aegis.policy;

/** What to do with a request that could not be inspected in full. Either way it is logged and counted. */
public enum FailAction {
    BLOCK,
    PASS
}
