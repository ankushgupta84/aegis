package io.aegis.observe;

import io.aegis.policy.LogSettings;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * Masks secrets before they reach the log. It is default-deny: header values are masked when the
 * name looks sensitive, query values are masked unless the name is allow-listed, and bodies are
 * never logged, only summarized. Logs outlive requests and are read by more people, so they must
 * be safe without configuration.
 */
public final class Redactor {

    public static final String REDACTED = "[redacted]";

    private static final Set<String> SENSITIVE_HEADERS =
            Set.of("authorization", "proxy-authorization", "cookie", "set-cookie");
    private static final List<String> SENSITIVE_NAME_PARTS =
            List.of("token", "secret", "api-key", "apikey", "password");

    private final Set<String> loggedQueryParams;

    public Redactor(LogSettings settings) {
        this.loggedQueryParams = Set.copyOf(settings.loggedQueryParams());
    }

    /** @return the value, or {@value #REDACTED} when the header name is sensitive */
    public String headerValue(String name, String value) {
        Objects.requireNonNull(value, "value");
        return isSensitiveHeader(name.toLowerCase(Locale.ROOT)) ? REDACTED : value;
    }

    /**
     * Keeps the path and every parameter name; masks each value unless its name is allow-listed.
     * Works on the raw text without decoding, so an encoded name cannot slip past the allow-list
     * and a malformed query cannot make it throw. Names match exactly, case included.
     */
    public String target(String rawTarget) {
        int queryStart = rawTarget.indexOf('?');
        if (queryStart < 0) {
            return rawTarget;
        }
        String[] parameters = rawTarget.substring(queryStart + 1).split("&", -1);
        for (int i = 0; i < parameters.length; i++) {
            parameters[i] = redactParameter(parameters[i]);
        }
        return rawTarget.substring(0, queryStart + 1) + String.join("&", parameters);
    }

    /** Request bodies are never logged; this is all the log gets to know about one. */
    public BodySummary body(byte[] body) {
        return new BodySummary(body.length, sha256Hex(body));
    }

    private boolean isSensitiveHeader(String lowerCaseName) {
        return SENSITIVE_HEADERS.contains(lowerCaseName)
                || SENSITIVE_NAME_PARTS.stream().anyMatch(lowerCaseName::contains);
    }

    private String redactParameter(String parameter) {
        int equals = parameter.indexOf('=');
        if (equals < 0) {
            return parameter; // a name with no value holds nothing to hide
        }
        String name = parameter.substring(0, equals);
        return loggedQueryParams.contains(name) ? parameter : name + "=" + REDACTED;
    }

    private static String sha256Hex(byte[] body) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(body));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Every Java runtime must provide SHA-256", e);
        }
    }
}
