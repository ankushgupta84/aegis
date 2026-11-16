package io.aegis.http;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ParsedRequestTest {

    private static Map.Entry<String, String> h(String name, String value) {
        return new SimpleEntry<>(name, value);
    }

    private static ParsedRequest request(String target, List<Map.Entry<String, String>> headers) {
        return ParsedRequest.of("GET", target, "HTTP/1.1", headers, new byte[0], 1024);
    }

    private static ParsedRequest withBody(int bodyLength, int limit) {
        return ParsedRequest.of("POST", "/", "HTTP/1.1", List.of(), new byte[bodyLength], limit);
    }

    @Test
    void exposesRequestLineParts() {
        ParsedRequest r = request("/a//b?x=%41", List.of());
        assertThat(r.method()).isEqualTo("GET");
        assertThat(r.rawTarget()).isEqualTo("/a//b?x=%41");
        assertThat(r.httpVersion()).isEqualTo("HTTP/1.1");
        assertThat(r.path()).isEqualTo("/a/b");
        assertThat(r.rawQuery()).isEqualTo("x=%41");
        assertThat(r.get(RuleBuffer.HTTP_URI)).isEqualTo("/a/b?x=A");
        assertThat(r.get(RuleBuffer.HTTP_URI_RAW)).isEqualTo("/a//b?x=%41");
        assertThat(r.get(RuleBuffer.HTTP_REQUEST_LINE)).isEqualTo("GET /a//b?x=%41 HTTP/1.1");
        assertThat(r.get(RuleBuffer.HTTP_METHOD)).isEqualTo("GET");
    }

    @Test
    void rawQueryIsEmptyWithoutQuestionMark() {
        assertThat(request("/a", List.of()).rawQuery()).isEmpty();
        assertThat(request("/a?", List.of()).rawQuery()).isEmpty();
    }

    @Test
    void rawQueryStartsAfterTheFirstQuestionMark() {
        assertThat(request("/a?b?c", List.of()).rawQuery()).isEqualTo("b?c");
    }

    @Test
    void headersKeepOrderAndDuplicates() {
        ParsedRequest r = request("/", List.of(h("A", "1"), h("B", "2"), h("a", "3")));
        assertThat(r.allHeaders()).extracting(Map.Entry::getValue).containsExactly("1", "2", "3");
        assertThat(r.header("A")).contains("1");
        assertThat(r.header("b")).contains("2");
        assertThat(r.headers("A")).containsExactly("1", "3");
        assertThat(r.header("missing")).isEmpty();
        assertThat(r.headers("missing")).isEmpty();
    }

    @Test
    void headerBufferListsLinesInOrderSent() {
        ParsedRequest r = request("/", List.of(h("Host", "x"), h("A", "1"), h("A", "2")));
        assertThat(r.get(RuleBuffer.HTTP_HEADER)).isEqualTo("Host: x\r\nA: 1\r\nA: 2\r\n");
    }

    @Test
    void hostIsLowercasedWithoutPort() {
        assertThat(request("/", List.of(h("Host", "Example.COM:8080"))).host()).isEqualTo("example.com");
        assertThat(request("/", List.of(h("host", "example.com"))).get(RuleBuffer.HTTP_HOST))
                .isEqualTo("example.com");
    }

    @Test
    void ipv6HostKeepsBracketsAndDropsPort() {
        assertThat(request("/", List.of(h("Host", "[::1]:8080"))).host()).isEqualTo("[::1]");
        assertThat(request("/", List.of(h("Host", "[::1]"))).host()).isEqualTo("[::1]");
    }

    @Test
    void missingHeadersGiveEmptyBuffers() {
        ParsedRequest r = request("/", List.of());
        for (RuleBuffer buffer : List.of(RuleBuffer.HTTP_HOST, RuleBuffer.HTTP_USER_AGENT,
                RuleBuffer.HTTP_COOKIE, RuleBuffer.HTTP_CONTENT_TYPE, RuleBuffer.HTTP_REQUEST_BODY,
                RuleBuffer.HTTP_HEADER)) {
            assertThat(r.get(buffer)).as(buffer.name()).isEmpty();
        }
        assertThat(r.host()).isEmpty();
    }

    @Test
    void headerValueBuffers() {
        ParsedRequest r = request("/", List.of(h("User-Agent", "ua"), h("Content-Type", "text/plain"),
                h("Cookie", "a=1"), h("Cookie", "b=2")));
        assertThat(r.get(RuleBuffer.HTTP_USER_AGENT)).isEqualTo("ua");
        assertThat(r.get(RuleBuffer.HTTP_CONTENT_TYPE)).isEqualTo("text/plain");
        assertThat(r.get(RuleBuffer.HTTP_COOKIE)).isEqualTo("a=1; b=2");
    }

    @Test
    void nonAsciiBytesSurviveTheLatin1RoundTrip() {
        byte[] bytes = {(byte) 0x00, (byte) 0x80, (byte) 0xC3, (byte) 0xFF};
        ParsedRequest r = ParsedRequest.of("POST", "/é", "HTTP/1.1",
                List.of(h("X", "ÿ")), bytes, 10);
        String body = r.get(RuleBuffer.HTTP_REQUEST_BODY);
        assertThat(body).hasSize(4);
        assertThat(body.getBytes(StandardCharsets.ISO_8859_1)).isEqualTo(bytes);
        assertThat(r.get(RuleBuffer.HTTP_URI_RAW)).isEqualTo("/é");
        assertThat(r.get(RuleBuffer.HTTP_HEADER)).isEqualTo("X: ÿ\r\n");
    }

    @Test
    void bodyAtExactlyTheLimitIsNotTruncated() {
        ParsedRequest r = withBody(8, 8);
        assertThat(r.bodyTruncated()).isFalse();
        assertThat(r.get(RuleBuffer.HTTP_REQUEST_BODY)).hasSize(8);
        assertThat(r.bodyLength()).isEqualTo(8);
    }

    @Test
    void bodyOneByteOverTheLimitIsTruncated() {
        ParsedRequest r = withBody(9, 8);
        assertThat(r.bodyTruncated()).isTrue();
        assertThat(r.get(RuleBuffer.HTTP_REQUEST_BODY)).hasSize(8);
        assertThat(r.bodyLength()).isEqualTo(9);
    }

    @Test
    void zeroLimitHidesTheWholeBody() {
        ParsedRequest r = withBody(3, 0);
        assertThat(r.get(RuleBuffer.HTTP_REQUEST_BODY)).isEmpty();
        assertThat(r.bodyTruncated()).isTrue();
    }

    @Test
    void emptyBodyIsNeverTruncated() {
        assertThat(withBody(0, 0).bodyTruncated()).isFalse();
    }

    @Test
    void negativeLimitIsRejectedWithGuidance() {
        assertThatThrownBy(() -> withBody(1, -1))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("0 or more");
    }

    @Test
    void textAboveLatin1IsRejectedWithGuidance() {
        assertThatThrownBy(() -> request("/€", List.of()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("ISO-8859-1");
    }

    @Test
    void laterChangesToCallerInputsDoNotAffectTheRequest() {
        List<Map.Entry<String, String>> headers = new ArrayList<>(List.of(h("A", "1")));
        byte[] body = {1, 2};
        ParsedRequest r = ParsedRequest.of("POST", "/", "HTTP/1.1", headers, body, 10);
        headers.add(h("B", "2"));
        body[0] = 9;
        assertThat(r.allHeaders()).hasSize(1);
        assertThat(r.get(RuleBuffer.HTTP_REQUEST_BODY)).isEqualTo("\u0001\u0002");
    }

    @Test
    void repeatedReadsReturnTheSameContent() {
        ParsedRequest r = request("/a%41", List.of());
        assertThat(r.get(RuleBuffer.HTTP_URI)).isEqualTo("/aA").isSameAs(r.get(RuleBuffer.HTTP_URI));
    }
}
