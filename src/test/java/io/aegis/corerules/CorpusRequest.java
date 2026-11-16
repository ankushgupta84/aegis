package io.aegis.corerules;

import io.aegis.http.ParsedRequest;
import java.nio.charset.StandardCharsets;
import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * One line of a corpus file. Text fields may carry the tokens {@code {CRLF}} and {@code {LF}} for line
 * breaks, and {@code headers} holds extra {@code Name: value} headers separated by {@code {H}}.
 */
record CorpusRequest(String id, String kind, String attackClass, String method, String target, String userAgent,
        String contentType, String headers, String body, String note, String reason) {

    private static final int BODY_SCAN_LIMIT = 1 << 20;

    static CorpusRequest of(String method, String target, String userAgent, String contentType, String body) {
        return new CorpusRequest("adhoc", "", "", method, target, userAgent, contentType, "", body, "", "");
    }

    static CorpusRequest get(String target, String userAgent) {
        return of("GET", target, userAgent, "", "");
    }

    ParsedRequest toParsedRequest() {
        byte[] bytes = lineBreaks(body).getBytes(StandardCharsets.ISO_8859_1);
        List<Map.Entry<String, String>> all = new ArrayList<>();
        all.add(header("Host", "shop.example.com"));
        if (!userAgent.isEmpty()) {
            all.add(header("User-Agent", userAgent));
        }
        if (!contentType.isEmpty()) {
            all.add(header("Content-Type", contentType));
        }
        if (bytes.length > 0) {
            all.add(header("Content-Length", Integer.toString(bytes.length)));
        }
        if (!headers.isEmpty()) {
            for (String line : headers.split("\\{H}")) {
                int colon = line.indexOf(": ");
                all.add(header(line.substring(0, colon), line.substring(colon + 2)));
            }
        }
        return ParsedRequest.of(method, target, "HTTP/1.1", all, bytes, BODY_SCAN_LIMIT);
    }

    private static Map.Entry<String, String> header(String name, String value) {
        return new SimpleImmutableEntry<>(name, value);
    }

    private static String lineBreaks(String text) {
        return text.replace("{CRLF}", "\r\n").replace("{LF}", "\n");
    }
}
