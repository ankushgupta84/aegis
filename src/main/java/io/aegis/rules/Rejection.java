package io.aegis.rules;

/**
 * Why one rule cannot be applied in full. Thrown while reading a rule and caught by the
 * classifier, which turns it into an UNSUPPORTED result; it never leaves this package.
 */
final class Rejection extends RuntimeException {

    private Rejection(String reason) {
        super(reason, null, false, false);
    }

    /** The rule text is malformed. */
    static Rejection syntax(String detail) {
        return new Rejection("syntax error: " + detail);
    }

    /** The rule uses a keyword outside the supported set. */
    static Rejection keyword(String keyword) {
        return new Rejection("uses keyword '" + keyword + "', which Aegis does not support");
    }

    /** The rule looks at server responses. */
    static Rejection response(String what) {
        return new Rejection(what + " inspects responses, which Aegis does not inspect yet");
    }

    /** Any other reason, already in plain language. */
    static Rejection because(String reason) {
        return new Rejection(reason);
    }
}
