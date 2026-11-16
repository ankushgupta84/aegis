package io.aegis.config;

import com.fasterxml.jackson.databind.JsonNode;
import io.aegis.net.Cidr;
import io.aegis.policy.BackendAddress;
import io.aegis.policy.Skip;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/** The kinds of value the configuration uses, each with its validation and its plain-language error. */
final class ValueTypes {
    static final ValueType<String> TEXT = ValueType.of(ValueTypes::text, text -> text);
    static final ValueType<Boolean> BOOLEAN = ValueType.of(ValueTypes::bool, String::valueOf);
    static final ValueType<Integer> BYTES_AS_INT = ValueType.of(ValueTypes::bytesAsInt, size -> Sizes.format(size));
    static final ValueType<Long> BYTES = ValueType.of(Sizes::parse, Sizes::format);
    static final ValueType<Duration> DURATION = ValueType.of(Durations::parse, Durations::format);
    static final ValueType<Cidr> CIDR = ValueType.of(node -> Cidr.parse(text(node)), Cidr::toString);
    static final ValueType<BackendAddress> BACKEND = ValueType.of(ValueTypes::backend, BackendAddress::toString);
    static final ValueType<Path> FILE = ValueType.of(node -> Path.of(text(node)), Path::toString);
    static final ValueType<String> HOSTNAME = ValueType.of(ValueTypes::hostname, host -> host);
    static final ValueType<String> PATH_PREFIX = ValueType.of(ValueTypes::pathPrefix, prefix -> prefix);
    static final ValueType<String> SHA256 = ValueType.of(ValueTypes::sha256, fingerprint -> fingerprint);
    static final ValueType<Skip> SKIP = ValueType.of(ValueTypes::skip, ValueTypes::showSkip);
    static final ValueType<Double> POSITIVE_NUMBER = ValueType.of(ValueTypes::positiveNumber, ValueTypes::showNumber);

    private static final Pattern HOSTNAME_SHAPE = Pattern.compile("\\*|(\\*\\.)?[a-z0-9][a-z0-9.-]*");
    private static final Pattern SHA256_SHAPE = Pattern.compile("[0-9a-f]{64}");

    private ValueTypes() {
    }

    /** A whole number from {@code min} to {@code max}. */
    static ValueType<Integer> integer(int min, int max) {
        return ValueType.of(node -> integer(node, min, max), String::valueOf);
    }

    /** One of {@code choices}, written exactly. */
    static ValueType<String> choice(Collection<String> choices) {
        return ValueType.of(node -> choice(node, choices), choice -> choice);
    }

    /** One constant of {@code type}, written in lowercase with underscores, e.g. {@code reverse_proxy}. */
    static <E extends Enum<E>> ValueType<E> enumeration(Class<E> type) {
        List<String> names = Arrays.stream(type.getEnumConstants()).map(ValueTypes::spell).toList();
        return ValueType.of(
                node -> type.getEnumConstants()[names.indexOf(choice(node, names))],
                ValueTypes::spell);
    }

    private static String spell(Enum<?> constant) {
        return constant.name().toLowerCase(Locale.ROOT);
    }

    private static String text(JsonNode node) {
        if (!node.isTextual() || node.asText().isBlank()) {
            throw new IllegalArgumentException("Expected text but found " + shown(node)
                    + ". Write a word or phrase, in quotes if it looks like a number.");
        }
        return node.asText();
    }

    private static boolean bool(JsonNode node) {
        if (!node.isBoolean()) {
            throw new IllegalArgumentException(shown(node) + " is not true or false. Write true or false.");
        }
        return node.asBoolean();
    }

    private static int integer(JsonNode node, int min, int max) {
        if (!node.isIntegralNumber() || !node.canConvertToInt() || node.asInt() < min || node.asInt() > max) {
            throw new IllegalArgumentException(shown(node) + " is not a whole number from " + min + " to " + max + ".");
        }
        return node.asInt();
    }

    private static int bytesAsInt(JsonNode node) {
        long bytes = Sizes.parse(node);
        if (bytes > Integer.MAX_VALUE) {
            throw new IllegalArgumentException(shown(node) + " is too large here. The most allowed is "
                    + Integer.MAX_VALUE + " bytes.");
        }
        return (int) bytes;
    }

    private static String choice(JsonNode node, Collection<String> choices) {
        String given = node.isTextual() ? node.asText() : node.toString();
        if (!choices.contains(given)) {
            throw new IllegalArgumentException(shown(node) + " is not one of: " + String.join(", ", choices) + ".");
        }
        return given;
    }

    private static BackendAddress backend(JsonNode node) {
        String text = text(node);
        int colon = text.lastIndexOf(':');
        String host = colon < 0 ? "" : text.substring(0, colon);
        boolean bracketed = host.startsWith("[") && host.endsWith("]");
        String bareHost = bracketed ? host.substring(1, host.length() - 1) : host;
        boolean validHost = !bareHost.isBlank() && !bareHost.contains("/") && !bareHost.contains(" ")
                && (bracketed || !bareHost.contains(":"));
        if (!validHost) {
            throw new IllegalArgumentException(shown(node)
                    + " is not a backend address. Write host:port, e.g. 10.0.0.5:8080 or [::1]:8080.");
        }
        try {
            int port = Integer.parseInt(text.substring(colon + 1));
            if (port >= 1 && port <= 65535) {
                return new BackendAddress(bareHost, port);
            }
        } catch (NumberFormatException e) {
            // Falls through to the shared error below.
        }
        throw new IllegalArgumentException(shown(node) + " has no valid port. Use a number from 1 to 65535.");
    }

    private static String hostname(JsonNode node) {
        String host = text(node).toLowerCase(Locale.ROOT);
        if (!HOSTNAME_SHAPE.matcher(host).matches()) {
            throw new IllegalArgumentException(shown(node) + " is not a host name. Write a name such as "
                    + "example.com, a wildcard such as *.example.com, or * for any host.");
        }
        return host;
    }

    private static String pathPrefix(JsonNode node) {
        String prefix = text(node);
        if (!prefix.startsWith("/")) {
            throw new IllegalArgumentException(shown(node) + " is not a path prefix. It must start with /, e.g. /api.");
        }
        return prefix;
    }

    private static String sha256(JsonNode node) {
        String digits = text(node).replace(":", "").toLowerCase(Locale.ROOT);
        if (!SHA256_SHAPE.matcher(digits).matches()) {
            throw new IllegalArgumentException(shown(node) + " is not a SHA-256 fingerprint. "
                    + "Write 64 hex digits; colons between bytes are allowed.");
        }
        return digits;
    }

    private static Skip skip(JsonNode node) {
        String text = text(node);
        String help = " is not something an exemption can skip. Write rate_limit, waf, rule_set:<name>, or sid:<number>.";
        if (text.equals("rate_limit")) {
            return Skip.rateLimit();
        }
        if (text.equals("waf")) {
            return Skip.waf();
        }
        if (text.startsWith("rule_set:") && text.length() > "rule_set:".length()) {
            return Skip.ruleSet(text.substring("rule_set:".length()));
        }
        if (text.startsWith("sid:")) {
            try {
                int sid = Integer.parseInt(text.substring("sid:".length()));
                if (sid > 0) {
                    return Skip.sid(sid);
                }
            } catch (NumberFormatException e) {
                // Falls through to the shared error below.
            }
        }
        throw new IllegalArgumentException(shown(node) + help);
    }

    private static String showSkip(Skip skip) {
        return switch (skip.kind()) {
            case RATE_LIMIT -> "rate_limit";
            case WAF -> "waf";
            case RULE_SET -> "rule_set:" + skip.target();
            case SID -> "sid:" + skip.target();
        };
    }

    private static double positiveNumber(JsonNode node) {
        if (!node.isNumber() || node.asDouble() <= 0) {
            throw new IllegalArgumentException(shown(node) + " is not a positive number, e.g. 100 or 2.5.");
        }
        return node.asDouble();
    }

    private static String showNumber(double number) {
        return number == Math.rint(number) ? Long.toString((long) number) : Double.toString(number);
    }

    private static String shown(JsonNode node) {
        return "'" + (node.isTextual() ? node.asText() : node.toString()) + "'";
    }
}
