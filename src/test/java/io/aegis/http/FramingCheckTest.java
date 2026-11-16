package io.aegis.http;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.AbstractMap.SimpleEntry;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class FramingCheckTest {

    @SafeVarargs
    private static Optional<String> check(Map.Entry<String, String>... headers) {
        return FramingCheck.violation(Arrays.asList(headers));
    }

    private static Map.Entry<String, String> h(String name, String value) {
        return new SimpleEntry<>(name, value);
    }

    @Test
    void noHeadersIsAccepted() {
        assertThat(FramingCheck.violation(List.of())).isEmpty();
    }

    @Test
    void ordinaryGetIsAccepted() {
        assertThat(check(h("Host", "example.com"), h("User-Agent", "curl"))).isEmpty();
    }

    @Test
    void singleContentLengthIsAccepted() {
        assertThat(check(h("Host", "a"), h("content-length", "42"))).isEmpty();
        assertThat(check(h("Content-Length", "0"))).isEmpty();
        assertThat(check(h("Content-Length", " 7 "))).isEmpty();
    }

    @Test
    void chunkedInAnyCaseIsAccepted() {
        assertThat(check(h("Transfer-Encoding", "chunked"))).isEmpty();
        assertThat(check(h("transfer-encoding", " Chunked "))).isEmpty();
    }

    @Test
    void contentLengthWithTransferEncodingIsRejected() {
        assertThat(check(h("Content-Length", "5"), h("Transfer-Encoding", "chunked")))
                .hasValueSatisfying(r -> assertThat(r).contains("both Content-Length and Transfer-Encoding"));
    }

    @Test
    void repeatedContentLengthIsRejectedEvenWhenIdentical() {
        assertThat(check(h("Content-Length", "5"), h("content-length", "5")))
                .hasValueSatisfying(r -> assertThat(r).contains("2 Content-Length"));
    }

    @Test
    void commaSeparatedContentLengthIsRejected() {
        assertThat(check(h("Content-Length", "5, 5"))).isPresent();
    }

    @Test
    void nonDigitContentLengthIsRejected() {
        for (String bad : List.of("", "abc", "-1", "+1", "1.5", "0x10", "1 2", "١")) {
            assertThat(check(h("Content-Length", bad))).as(bad).isPresent();
        }
    }

    @Test
    void transferEncodingOtherThanChunkedIsRejected() {
        for (String bad : List.of("gzip", "chunked, gzip", "gzip, chunked", "identity", "xchunked", "")) {
            assertThat(check(h("Transfer-Encoding", bad))).as(bad).isPresent();
        }
    }

    @Test
    void repeatedTransferEncodingIsRejected() {
        assertThat(check(h("Transfer-Encoding", "chunked"), h("Transfer-Encoding", "chunked"))).isPresent();
    }

    @Test
    void multipleHostHeadersAreRejected() {
        assertThat(check(h("Host", "a"), h("HOST", "b")))
                .hasValueSatisfying(r -> assertThat(r).contains("more than one Host"));
    }

    @Test
    void headerNamesWithWhitespaceOrControlCharactersAreRejected() {
        for (String bad : List.of("Content-Length ", " Host", "Trans fer", "X\tY", "X\r", "X\0", "X\u007F", "")) {
            assertThat(check(h(bad, "v"))).as("name: " + bad.replace("\0", "NUL")).isPresent();
        }
    }
}
