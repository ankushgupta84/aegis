package io.aegis.rules;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import org.junit.jupiter.api.Test;

class OptionSplitterTest {

    @Test
    void options_split_into_name_and_value() {
        assertThat(OptionSplitter.split("msg:\"x\"; sid:1;"))
                .containsExactly(new RuleOption("msg", "\"x\""), new RuleOption("sid", "1"));
    }

    @Test
    void keyword_without_value_has_an_empty_value() {
        List<RuleOption> options = OptionSplitter.split("http.uri; nocase;");
        assertThat(options).containsExactly(new RuleOption("http.uri", ""), new RuleOption("nocase", ""));
        assertThat(options.get(0).hasValue()).isFalse();
    }

    @Test
    void semicolon_inside_quotes_does_not_split() {
        assertThat(OptionSplitter.split("content:\"a;b\"; sid:1;"))
                .containsExactly(new RuleOption("content", "\"a;b\""), new RuleOption("sid", "1"));
    }

    @Test
    void escaped_quote_does_not_end_the_quoted_value() {
        assertThat(OptionSplitter.split("msg:\"say \\\"hi;\\\" now\"; sid:1;"))
                .containsExactly(new RuleOption("msg", "\"say \\\"hi;\\\" now\""), new RuleOption("sid", "1"));
    }

    @Test
    void escaped_semicolon_outside_quotes_does_not_split() {
        assertThat(OptionSplitter.split("msg:a\\;b; sid:1;")).extracting(RuleOption::value).containsExactly("a\\;b", "1");
    }

    @Test
    void escaped_backslash_before_closing_quote_still_closes_it() {
        assertThat(OptionSplitter.split("content:\"a\\\\\"; sid:1;")).extracting(RuleOption::name).containsExactly("content", "sid");
    }

    @Test
    void only_the_first_colon_separates_name_from_value() {
        assertThat(OptionSplitter.split("metadata:a b, c d:e;")).containsExactly(new RuleOption("metadata", "a b, c d:e"));
    }

    @Test
    void blanks_around_names_and_values_are_trimmed() {
        assertThat(OptionSplitter.split("  sid : 5 ;")).containsExactly(new RuleOption("sid", "5"));
    }

    @Test
    void stray_semicolons_are_ignored() {
        assertThat(OptionSplitter.split("sid:1;; ;")).hasSize(1);
    }

    @Test
    void unterminated_quote_is_a_syntax_error() {
        assertThatThrownBy(() -> OptionSplitter.split("msg:\"oops; sid:1;"))
                .isInstanceOf(Rejection.class).hasMessageStartingWith("syntax error").hasMessageContaining("quote");
    }

    @Test
    void last_option_without_semicolon_is_a_syntax_error() {
        assertThatThrownBy(() -> OptionSplitter.split("sid:1; rev:2"))
                .isInstanceOf(Rejection.class).hasMessageContaining("not terminated");
    }
}
