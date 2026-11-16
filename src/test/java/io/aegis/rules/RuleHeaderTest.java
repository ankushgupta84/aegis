package io.aegis.rules;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class RuleHeaderTest {

    @Test
    void simple_header_yields_action_protocol_and_options() {
        RuleHeader header = RuleHeader.parse("alert http any any -> any any (sid:1;)");
        assertThat(header.action()).isEqualTo("alert");
        assertThat(header.protocol()).isEqualTo("http");
        assertThat(header.optionText()).isEqualTo("sid:1;");
    }

    @Test
    void variables_negations_and_bracketed_lists_with_blanks_parse_past() {
        RuleHeader header = RuleHeader.parse(
                "drop tcp [$HOME_NET,!10.0.0.1] [1024:65535,!8080] <> [1.1.1.1, 2.2.2.2/24] [80, 443] (sid:2;)");
        assertThat(header.action()).isEqualTo("drop");
        assertThat(header.optionText()).isEqualTo("sid:2;");
    }

    @Test
    void nested_brackets_parse() {
        assertThat(RuleHeader.parse("alert http [[1.1.1.1,2.2.2.2],!3.3.3.3] any -> any any (sid:1;)").optionText())
                .isEqualTo("sid:1;");
    }

    @Test
    void parentheses_inside_options_are_kept() {
        assertThat(RuleHeader.parse("alert http any any -> any any (msg:\"a (b)\"; sid:1;)").optionText())
                .isEqualTo("msg:\"a (b)\"; sid:1;");
    }

    @Test
    void trailing_blanks_after_the_closing_parenthesis_are_allowed() {
        assertThat(RuleHeader.parse("alert http any any -> any any (sid:1;)   ").optionText()).isEqualTo("sid:1;");
    }

    @Test
    void too_few_fields_is_a_syntax_error() {
        assertThatThrownBy(() -> RuleHeader.parse("alert http any any (sid:1;)"))
                .isInstanceOf(Rejection.class).hasMessageStartingWith("syntax error");
    }

    @Test
    void missing_options_is_a_syntax_error() {
        assertThatThrownBy(() -> RuleHeader.parse("alert http any any -> any any"))
                .isInstanceOf(Rejection.class).hasMessageContaining("parentheses");
    }

    @Test
    void unclosed_options_is_a_syntax_error() {
        assertThatThrownBy(() -> RuleHeader.parse("alert http any any -> any any (sid:1;"))
                .isInstanceOf(Rejection.class).hasMessageContaining("parentheses");
    }

    @Test
    void unknown_action_is_a_syntax_error() {
        assertThatThrownBy(() -> RuleHeader.parse("explode http any any -> any any (sid:1;)"))
                .isInstanceOf(Rejection.class).hasMessageContaining("action 'explode'");
    }

    @Test
    void unknown_direction_is_a_syntax_error() {
        assertThatThrownBy(() -> RuleHeader.parse("alert http any any <- any any (sid:1;)"))
                .isInstanceOf(Rejection.class).hasMessageContaining("direction");
    }

    @Test
    void unbalanced_bracket_is_a_syntax_error() {
        assertThatThrownBy(() -> RuleHeader.parse("alert http [1.1.1.1 any -> any any (sid:1;)"))
                .isInstanceOf(Rejection.class).hasMessageContaining("unbalanced");
    }
}
