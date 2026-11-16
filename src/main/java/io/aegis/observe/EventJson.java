package io.aegis.observe;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Map;

/** Renders an event as one line of JSON: timestamp, type, then the fields in insertion order. */
final class EventJson {

    static final String TIMESTAMP = "ts";
    static final String TYPE = "type";

    // Fixed three-digit milliseconds: Instant.toString drops the fraction when it is zero,
    // which would make timestamps in one log differ in width.
    private static final DateTimeFormatter MILLIS_UTC =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(ZoneOffset.UTC);

    private final ObjectMapper mapper = new ObjectMapper();

    String line(Event event, Instant at) throws JsonProcessingException {
        Map<String, Object> ordered = new LinkedHashMap<>();
        ordered.put(TIMESTAMP, MILLIS_UTC.format(at));
        ordered.put(TYPE, event.type());
        ordered.putAll(event.fields());
        return mapper.writeValueAsString(ordered);
    }
}
