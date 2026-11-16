package io.aegis.observe;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * One structured log event: a type plus named fields, kept in insertion order so every line of
 * the log reads the same way. An event must not be changed after it is passed to
 * {@link EventLog#write}, because the log serializes it later on its own thread.
 */
public final class Event {

    private final String type;
    private final Map<String, Object> fields = new LinkedHashMap<>();

    private Event(String type) {
        this.type = type;
    }

    /** @param type the kind of event, such as {@code request} or {@code waf_block} */
    public static Event of(String type) {
        return new Event(Objects.requireNonNull(type, "type"));
    }

    /**
     * Adds a field. Values may be String, Number, Boolean, or Lists and Maps of those; a null
     * value is omitted, so optional data needs no caller-side branching.
     *
     * @throws IllegalArgumentException if the name is already used, including {@code ts} and
     *                                  {@code type}, which the log writes itself
     */
    public Event with(String field, Object value) {
        Objects.requireNonNull(field, "field");
        if (field.equals(EventJson.TIMESTAMP) || field.equals(EventJson.TYPE) || fields.containsKey(field)) {
            throw new IllegalArgumentException("Event field '" + field + "' is reserved or already set on this " + type + " event");
        }
        if (value != null) {
            fields.put(field, value);
        }
        return this;
    }

    String type() {
        return type;
    }

    Map<String, Object> fields() {
        return fields;
    }
}
