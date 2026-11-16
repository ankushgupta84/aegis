package io.aegis.rules;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.aegis.http.RuleBuffer;
import org.junit.jupiter.api.Test;

class PcreTranslatorTest {

    @Test
    void expression_and_flags_are_split_at_the_last_slash() {
        ParsedPcre pcre = PcreTranslator.parse("\"/a\\/b/is\"");
        assertThat(pcre.regex()).isEqualTo("a\\/b");
        assertThat(pcre.caseInsensitive()).isTrue();
        assertThat(pcre.dotAll()).isTrue();
        assertThat(pcre.multiline()).isFalse();
    }

    @Test
    void multiline_and_relative_flags_are_recorded() {
        ParsedPcre pcre = PcreTranslator.parse("\"/x/mR\"");
        assertThat(pcre.multiline()).isTrue();
        assertThat(pcre.relative()).isTrue();
    }

    @Test
    void leading_bang_negates() {
        assertThat(PcreTranslator.parse("!\"/x/\"").negated()).isTrue();
        assertThat(PcreTranslator.parse("\"/x/\"").negated()).isFalse();
    }

    @Test
    void each_buffer_flag_maps_to_its_buffer() {
        assertThat(PcreTranslator.parse("\"/x/U\"").bufferFlag()).isEqualTo(RuleBuffer.HTTP_URI);
        assertThat(PcreTranslator.parse("\"/x/I\"").bufferFlag()).isEqualTo(RuleBuffer.HTTP_URI_RAW);
        assertThat(PcreTranslator.parse("\"/x/H\"").bufferFlag()).isEqualTo(RuleBuffer.HTTP_HEADER);
        assertThat(PcreTranslator.parse("\"/x/P\"").bufferFlag()).isEqualTo(RuleBuffer.HTTP_REQUEST_BODY);
        assertThat(PcreTranslator.parse("\"/x/C\"").bufferFlag()).isEqualTo(RuleBuffer.HTTP_COOKIE);
        assertThat(PcreTranslator.parse("\"/x/M\"").bufferFlag()).isEqualTo(RuleBuffer.HTTP_METHOD);
        assertThat(PcreTranslator.parse("\"/x/V\"").bufferFlag()).isEqualTo(RuleBuffer.HTTP_USER_AGENT);
        assertThat(PcreTranslator.parse("\"/x/W\"").bufferFlag()).isEqualTo(RuleBuffer.HTTP_HOST);
        assertThat(PcreTranslator.parse("\"/x/\"").bufferFlag()).isNull();
    }

    @Test
    void unlisted_flag_is_unsupported() {
        assertThatThrownBy(() -> PcreTranslator.parse("\"/x/A\""))
                .isInstanceOf(Rejection.class).hasMessageContaining("flag 'A'");
    }

    @Test
    void two_buffer_flags_are_a_syntax_error() {
        assertThatThrownBy(() -> PcreTranslator.parse("\"/x/UH\""))
                .isInstanceOf(Rejection.class).hasMessageContaining("two buffers");
    }

    @Test
    void lookahead_is_refused_because_a_linear_time_engine_cannot_provide_it() {
        assertThatThrownBy(() -> PcreTranslator.parse("\"/a(?=b)/\""))
                .isInstanceOf(Rejection.class)
                .hasMessageStartingWith("pcre needs a feature a linear-time engine cannot provide");
    }

    @Test
    void lookbehind_backreference_and_possessive_quantifier_are_refused() {
        assertThatThrownBy(() -> PcreTranslator.parse("\"/(?<=a)b/\"")).isInstanceOf(Rejection.class);
        assertThatThrownBy(() -> PcreTranslator.parse("\"/(a)\\1/\"")).isInstanceOf(Rejection.class);
        assertThatThrownBy(() -> PcreTranslator.parse("\"/a++/\"")).isInstanceOf(Rejection.class);
    }

    @Test
    void expression_without_slashes_is_a_syntax_error() {
        assertThatThrownBy(() -> PcreTranslator.parse("\"abc\""))
                .isInstanceOf(Rejection.class).hasMessageStartingWith("syntax error");
        assertThatThrownBy(() -> PcreTranslator.parse("\"/abc\"")).isInstanceOf(Rejection.class);
    }

    @Test
    void unquoted_value_is_a_syntax_error() {
        assertThatThrownBy(() -> PcreTranslator.parse("/abc/")).isInstanceOf(Rejection.class);
    }

    @Test
    void a_pcre_becomes_a_condition_on_the_chosen_buffer() {
        PcreMatch match = PcreTranslator.parse("!\"/x/iR\"").on(RuleBuffer.HTTP_URI, java.util.List.of(Transform.URL_DECODE));
        assertThat(match.buffer()).isEqualTo(RuleBuffer.HTTP_URI);
        assertThat(match.transforms()).containsExactly(Transform.URL_DECODE);
        assertThat(match.negated()).isTrue();
        assertThat(match.caseInsensitive()).isTrue();
        assertThat(match.relative()).isTrue();
    }
}
