package io.aegis.observe;

import static org.assertj.core.api.Assertions.assertThat;

import io.aegis.policy.LogSettings;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class RedactorTest {

    private final Redactor redactor = new Redactor(new LogSettings(Path.of("."), 1, 1, List.of("page", "sort")));

    @ParameterizedTest
    @ValueSource(strings = {"Authorization", "proxy-authorization", "COOKIE", "Set-Cookie", "X-Auth-Token",
            "X-Client-Secret", "X-Api-Key", "X-APIKEY", "X-Password"})
    void sensitive_header_values_are_redacted(String name) {
        assertThat(redactor.headerValue(name, "hunter2")).isEqualTo("[redacted]");
    }

    @ParameterizedTest
    @ValueSource(strings = {"Host", "User-Agent", "Content-Type", "X-Request-Id"})
    void other_header_values_are_kept(String name) {
        assertThat(redactor.headerValue(name, "v")).isEqualTo("v");
    }

    @Test
    void target_without_query_is_unchanged() {
        assertThat(redactor.target("/a/b")).isEqualTo("/a/b");
    }

    @Test
    void query_values_are_redacted_unless_the_name_is_allow_listed() {
        assertThat(redactor.target("/s?page=2&q=secret&sort=asc&id=7"))
                .isEqualTo("/s?page=2&q=[redacted]&sort=asc&id=[redacted]");
    }

    @Test
    void query_names_are_matched_exactly_without_decoding() {
        assertThat(redactor.target("/s?Page=2&pa%67e=3")).isEqualTo("/s?Page=[redacted]&pa%67e=[redacted]");
    }

    @Test
    void value_containing_equals_is_redacted_whole() {
        assertThat(redactor.target("/s?a=b=c")).isEqualTo("/s?a=[redacted]");
    }

    @Test
    void malformed_queries_never_throw() {
        assertThat(redactor.target("/s?a")).isEqualTo("/s?a");
        assertThat(redactor.target("/s?=b")).isEqualTo("/s?=[redacted]");
        assertThat(redactor.target("/s?&&")).isEqualTo("/s?&&");
        assertThat(redactor.target("/s?")).isEqualTo("/s?");
        assertThat(redactor.target("?")).isEqualTo("?");
    }

    @Test
    void body_summary_holds_length_and_sha256_of_the_bytes() {
        BodySummary summary = redactor.body("abc".getBytes(StandardCharsets.UTF_8));

        assertThat(summary.length()).isEqualTo(3);
        assertThat(summary.sha256Hex()).isEqualTo("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }

    @Test
    void empty_body_has_the_known_empty_digest() {
        assertThat(redactor.body(new byte[0]).sha256Hex())
                .isEqualTo("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    }
}
