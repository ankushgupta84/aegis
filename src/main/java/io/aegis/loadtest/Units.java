package io.aegis.loadtest;

import java.time.Duration;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses command line quantities such as {@code 600s} and {@code 64KB}. The unit is mandatory:
 * a bare {@code 600} could mean seconds or milliseconds, and guessing would corrupt a benchmark.
 */
final class Units {

    private static final Pattern QUANTITY = Pattern.compile("(\\d+)([a-zA-Z]+)");

    private Units() {
    }

    static Duration parseDuration(String flag, String text) {
        Matcher quantity = match(flag, text, "a duration such as 500ms, 5s, 2m or 1h");
        long amount = Long.parseLong(quantity.group(1));
        return switch (quantity.group(2).toLowerCase(Locale.ROOT)) {
            case "ms" -> Duration.ofMillis(amount);
            case "s" -> Duration.ofSeconds(amount);
            case "m" -> Duration.ofMinutes(amount);
            case "h" -> Duration.ofHours(amount);
            default -> throw invalid(flag, text, "a duration such as 500ms, 5s, 2m or 1h");
        };
    }

    static int parseSizeBytes(String flag, String text) {
        Matcher quantity = match(flag, text, "a size such as 512B, 1KB or 2MB");
        long amount = Long.parseLong(quantity.group(1));
        long bytes = switch (quantity.group(2).toUpperCase(Locale.ROOT)) {
            case "B" -> amount;
            case "KB" -> amount * 1024;
            case "MB" -> amount * 1024 * 1024;
            default -> throw invalid(flag, text, "a size such as 512B, 1KB or 2MB");
        };
        if (bytes > Integer.MAX_VALUE) {
            throw invalid(flag, text, "a size below 2GB");
        }
        return (int) bytes;
    }

    static long parsePositiveLong(String flag, String text) {
        try {
            long value = Long.parseLong(text);
            if (value < 1) {
                throw invalid(flag, text, "a whole number of at least 1");
            }
            return value;
        } catch (NumberFormatException e) {
            throw invalid(flag, text, "a whole number of at least 1");
        }
    }

    static long parseLong(String flag, String text) {
        try {
            return Long.parseLong(text);
        } catch (NumberFormatException e) {
            throw invalid(flag, text, "a whole number");
        }
    }

    static double parseShare(String flag, String text) {
        try {
            double value = Double.parseDouble(text);
            if (value >= 0 && value <= 1) {
                return value;
            }
        } catch (NumberFormatException e) {
            // reported below, with the other out-of-range case
        }
        throw invalid(flag, text, "a fraction between 0 and 1");
    }

    private static Matcher match(String flag, String text, String expected) {
        Matcher quantity = QUANTITY.matcher(text);
        if (!quantity.matches()) {
            throw invalid(flag, text, expected);
        }
        return quantity;
    }

    private static UsageException invalid(String flag, String text, String expected) {
        return new UsageException(flag + ": '" + text + "' is not " + expected);
    }
}
