package io.aegis.http;

/**
 * What the rule engine reads from a request. Keeping this to one method lets the engine be tested
 * with a plain map, with no HTTP parsing involved.
 */
@FunctionalInterface
public interface RequestBuffers {

    /**
     * The content of {@code buffer}, one char per byte.
     *
     * @return the content, or the empty string when the request has none; never null
     */
    String get(RuleBuffer buffer);
}
