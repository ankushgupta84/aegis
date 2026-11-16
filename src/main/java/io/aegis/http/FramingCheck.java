package io.aegis.http;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Request-smuggling defence. Two parties that disagree about where a request ends can be made to
 * read one request as two, so Aegis refuses any request whose framing is ambiguous instead of
 * choosing an interpretation. The proxy answers 400 when {@link #violation} returns a reason.
 *
 * <p>This is deliberately stricter than the HTTP specification: every repeated framing header is
 * rejected, even when the copies agree.
 */
public final class FramingCheck {

    private FramingCheck() {}

    /**
     * @return a plain-language reason when framing is ambiguous, otherwise empty
     */
    public static Optional<String> violation(List<Map.Entry<String, String>> headers) {
        for (Map.Entry<String, String> header : headers) {
            if (hasWhitespaceOrControl(header.getKey())) {
                return Optional.of("A header name contains whitespace or a control character. "
                        + "Header names must be plain token characters such as 'Content-Length'.");
            }
        }
        List<String> contentLengths = values(headers, "Content-Length");
        List<String> transferEncodings = values(headers, "Transfer-Encoding");

        if (!contentLengths.isEmpty() && !transferEncodings.isEmpty()) {
            return Optional.of("The request has both Content-Length and Transfer-Encoding, "
                    + "so its length is ambiguous. Send only one of them.");
        }
        if (contentLengths.size() > 1) {
            return Optional.of("The request has " + contentLengths.size() + " Content-Length "
                    + "headers. Send exactly one.");
        }
        if (contentLengths.size() == 1 && !isPlainDigits(contentLengths.get(0))) {
            return Optional.of("Content-Length '" + contentLengths.get(0) + "' is not valid. "
                    + "It must be a single number made of the digits 0-9, such as '42'.");
        }
        if (transferEncodings.size() > 1) {
            return Optional.of("The request has " + transferEncodings.size()
                    + " Transfer-Encoding headers. Send exactly one.");
        }
        if (transferEncodings.size() == 1 && !transferEncodings.get(0).strip().equalsIgnoreCase("chunked")) {
            return Optional.of("Transfer-Encoding '" + transferEncodings.get(0) + "' is not "
                    + "supported. The only accepted value is 'chunked'.");
        }
        if (values(headers, "Host").size() > 1) {
            return Optional.of("The request has more than one Host header. Send exactly one.");
        }
        return Optional.empty();
    }

    private static List<String> values(List<Map.Entry<String, String>> headers, String name) {
        return headers.stream()
                .filter(h -> h.getKey().equalsIgnoreCase(name))
                .map(Map.Entry::getValue)
                .toList();
    }

    private static boolean isPlainDigits(String value) {
        String trimmed = value.strip();
        return !trimmed.isEmpty() && trimmed.chars().allMatch(c -> c >= '0' && c <= '9');
    }

    private static boolean hasWhitespaceOrControl(String name) {
        return name.isEmpty() || name.chars().anyMatch(c -> c <= 0x20 || c == 0x7F);
    }
}
