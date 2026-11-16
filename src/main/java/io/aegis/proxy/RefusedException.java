package io.aegis.proxy;

/**
 * Raised inside the client pipeline, by a handler that cannot answer the client itself, to ask the
 * request handler to refuse. Carries no stack trace: it is control flow, not a fault.
 *
 * @param method the request method if the head was parsed, otherwise null
 * @param target the request target if the head was parsed, otherwise null
 */
final class RefusedException extends RuntimeException {

    private final transient Refusal refusal;
    private final String method;
    private final String target;

    RefusedException(Refusal refusal, String method, String target) {
        super(refusal.reason(), null, false, false);
        this.refusal = refusal;
        this.method = method;
        this.target = target;
    }

    Refusal refusal() {
        return refusal;
    }

    String method() {
        return method;
    }

    String target() {
        return target;
    }
}
