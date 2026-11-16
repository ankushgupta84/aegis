package io.aegis.config;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Byte sizes written as a whole number with a unit (B, KB, MB, GB; powers of 1024), or bare bytes. */
final class Sizes {
    private static final Pattern SIZE = Pattern.compile("(\\d{1,12})(B|KB|MB|GB)?");
    private static final String HELP = "Write a whole number and a unit, e.g. 512B, 16KB, 10MB, 1GB. "
            + "A bare number means bytes.";

    private Sizes() {
    }

    static long parse(JsonNode node) {
        Matcher matcher = SIZE.matcher(textOf(node));
        if (!matcher.matches()) {
            throw new IllegalArgumentException("'" + textOf(node) + "' is not a size. " + HELP);
        }
        long bytes = scale(Long.parseLong(matcher.group(1)), matcher.group(2));
        if (bytes == 0) {
            throw new IllegalArgumentException("A size must be greater than zero. " + HELP);
        }
        return bytes;
    }

    static String format(long bytes) {
        String[] units = {"GB", "MB", "KB"};
        for (int i = 0; i < units.length; i++) {
            long unit = 1L << (10 * (3 - i));
            if (bytes % unit == 0) {
                return bytes / unit + units[i];
            }
        }
        return bytes + "B";
    }

    private static long scale(long number, String unit) {
        if (unit == null) {
            return number;
        }
        int shift = switch (unit) {
            case "KB" -> 10;
            case "MB" -> 20;
            case "GB" -> 30;
            default -> 0;
        };
        if (number > Long.MAX_VALUE >> shift) {
            throw new IllegalArgumentException("'" + number + unit + "' is too large to be a size.");
        }
        return number << shift;
    }

    private static String textOf(JsonNode node) {
        return node.isTextual() ? node.asText() : node.toString();
    }
}
