package io.aegis.config;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.function.Function;

/**
 * How one kind of value is read from a YAML node and written back for display.
 *
 * <p>{@link #parse} reports a bad value by throwing {@link IllegalArgumentException} whose message
 * says what is wrong and what a valid value looks like.
 */
interface ValueType<T> {
    T parse(JsonNode node);

    String show(T value);

    static <T> ValueType<T> of(Function<JsonNode, T> parse, Function<T, String> show) {
        return new ValueType<>() {
            @Override
            public T parse(JsonNode node) {
                return parse.apply(node);
            }

            @Override
            public String show(T value) {
                return show.apply(value);
            }
        };
    }
}
