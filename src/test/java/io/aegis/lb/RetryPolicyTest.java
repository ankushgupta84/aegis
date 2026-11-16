package io.aegis.lb;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class RetryPolicyTest {

    @ParameterizedTest
    @ValueSource(strings = {"GET", "HEAD", "OPTIONS", "PUT", "DELETE", "POST", "PATCH", "PURGE", "get"})
    void any_method_may_retry_when_the_request_never_reached_a_backend(String method) {
        assertThat(RetryPolicy.mayRetry(method, false)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"GET", "HEAD", "OPTIONS", "PUT", "DELETE"})
    void idempotent_methods_may_retry_after_bytes_were_sent(String method) {
        assertThat(RetryPolicy.mayRetry(method, true)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"POST", "PATCH", "CONNECT", "TRACE", "PURGE", "get", "Get", ""})
    void other_methods_never_retry_after_bytes_were_sent(String method) {
        assertThat(RetryPolicy.mayRetry(method, true)).isFalse();
    }

    @Test
    void method_comparison_is_case_sensitive() {
        assertThat(RetryPolicy.mayRetry("delete", true)).isFalse();
    }
}
