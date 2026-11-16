package io.aegis.config;

import com.fasterxml.jackson.databind.JsonNode;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Durations written as a whole number and a unit (ms, s, m, h). A bare number is refused because
 * it does not say whether it means milliseconds or seconds.
 */
final class Durations {
    private static final Pattern DURATION = Pattern.compile("(\\d{1,9})(ms|s|m|h)");
    private static final String HELP = "Write a number and a unit, e.g. 500ms, 5s, 2m.";

    private Durations() {
    }

    static Duration parse(JsonNode node) {
        String text = node.isTextual() ? node.asText() : node.toString();
        Matcher matcher = DURATION.matcher(text);
        if (!matcher.matches()) {
            throw new IllegalArgumentException("'" + text + "' is not a duration. " + HELP);
        }
        Duration duration = Duration.of(Long.parseLong(matcher.group(1)), unit(matcher.group(2)));
        if (duration.isZero()) {
            throw new IllegalArgumentException("A duration must be longer than zero. " + HELP);
        }
        return duration;
    }

    static String format(Duration duration) {
        long millis = duration.toMillis();
        if (millis % 3_600_000 == 0) {
            return millis / 3_600_000 + "h";
        }
        if (millis % 60_000 == 0) {
            return millis / 60_000 + "m";
        }
        if (millis % 1000 == 0) {
            return millis / 1000 + "s";
        }
        return millis + "ms";
    }

    private static ChronoUnit unit(String suffix) {
        return switch (suffix) {
            case "ms" -> ChronoUnit.MILLIS;
            case "s" -> ChronoUnit.SECONDS;
            case "m" -> ChronoUnit.MINUTES;
            default -> ChronoUnit.HOURS;
        };
    }
}
