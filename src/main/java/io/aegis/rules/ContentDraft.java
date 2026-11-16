package io.aegis.rules;

import io.aegis.http.RuleBuffer;
import java.util.List;
import java.util.OptionalInt;

/**
 * A {@code content} keyword still collecting the modifiers that follow it. The rule reader turns
 * it into a {@link ContentMatch} once the next condition or buffer starts and no more modifiers
 * can arrive.
 */
final class ContentDraft {

    private final String pattern;
    private final boolean negated;
    private boolean nocase;
    private OptionalInt offset = OptionalInt.empty();
    private OptionalInt depth = OptionalInt.empty();
    private OptionalInt distance = OptionalInt.empty();
    private OptionalInt within = OptionalInt.empty();
    private boolean startsWith;
    private boolean endsWith;
    private boolean fastPattern;
    private RuleBuffer legacyBuffer;
    private boolean bufferUnknown;

    ContentDraft(String pattern, boolean negated) {
        this.pattern = pattern;
        this.negated = negated;
    }

    void nocase() {
        nocase = true;
    }

    void startsWith() {
        startsWith = true;
    }

    void endsWith() {
        endsWith = true;
    }

    void fastPattern() {
        fastPattern = true;
    }

    void offset(int value) {
        offset = OptionalInt.of(value);
    }

    void depth(int value) {
        depth = OptionalInt.of(value);
    }

    void distance(int value) {
        distance = OptionalInt.of(value);
    }

    void within(int value) {
        within = OptionalInt.of(value);
    }

    /** A legacy modifier such as {@code http_uri} names the buffer for this content alone. */
    void useBuffer(RuleBuffer buffer) {
        if (legacyBuffer != null || bufferUnknown) {
            throw Rejection.syntax("content names its buffer twice");
        }
        legacyBuffer = buffer;
    }

    /** A modifier Aegis does not know may have chosen a buffer; the reader must not call this content raw payload. */
    void markBufferUnknown() {
        bufferUnknown = true;
    }

    /** The buffer named by a legacy modifier, or null. */
    RuleBuffer legacyBuffer() {
        return legacyBuffer;
    }

    boolean bufferUnknown() {
        return bufferUnknown;
    }

    ContentMatch on(RuleBuffer buffer, List<Transform> transforms) {
        return new ContentMatch(buffer, transforms, pattern, negated, nocase, offset, depth, distance, within,
                startsWith, endsWith, fastPattern);
    }
}
