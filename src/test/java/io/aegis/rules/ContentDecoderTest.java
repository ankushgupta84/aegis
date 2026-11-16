package io.aegis.rules;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class ContentDecoderTest {

    @Test
    void plain_text_decodes_to_itself() {
        assertThat(ContentDecoder.decode("GET /index.html")).isEqualTo("GET /index.html");
    }

    @Test
    void hex_section_decodes_to_one_char_per_byte() {
        assertThat(ContentDecoder.decode("|48 54 54 50|")).isEqualTo("HTTP");
    }

    @Test
    void hex_crlf_becomes_carriage_return_and_line_feed() {
        assertThat(ContentDecoder.decode("|0d 0a|")).isEqualTo("\r\n");
    }

    @Test
    void bytes_above_seven_bits_become_chars_up_to_255() {
        assertThat(ContentDecoder.decode("|ff|SMB")).isEqualTo("ÿSMB");
    }

    @Test
    void hex_digits_may_be_upper_case_and_unspaced() {
        assertThat(ContentDecoder.decode("|0D0A|")).isEqualTo("\r\n");
    }

    @Test
    void text_and_hex_sections_mix_in_order() {
        assertThat(ContentDecoder.decode("Host|3a 20|evil|0d 0a|")).isEqualTo("Host: evil\r\n");
    }

    @Test
    void two_hex_sections_in_a_row_both_decode() {
        assertThat(ContentDecoder.decode("|41||42|")).isEqualTo("AB");
    }

    @Test
    void escaped_quote_semicolon_backslash_colon_and_pipe_stand_for_themselves() {
        assertThat(ContentDecoder.decode("a\\\"b\\;c\\\\d\\:e\\|f")).isEqualTo("a\"b;c\\d:e|f");
    }

    @Test
    void escaped_pipe_does_not_start_a_hex_section() {
        assertThat(ContentDecoder.decode("\\|41\\|")).isEqualTo("|41|");
    }

    @Test
    void a_colon_inside_hex_decodes_as_a_byte() {
        assertThat(ContentDecoder.decode("|3a|")).isEqualTo(":");
    }

    @Test
    void unterminated_hex_section_is_a_syntax_error() {
        assertThatThrownBy(() -> ContentDecoder.decode("abc|41"))
                .isInstanceOf(Rejection.class).hasMessageContaining("closing '|'");
    }

    @Test
    void non_hex_digit_is_a_syntax_error() {
        assertThatThrownBy(() -> ContentDecoder.decode("|4g|"))
                .isInstanceOf(Rejection.class).hasMessageContaining("not a hex byte");
    }

    @Test
    void half_a_hex_byte_is_a_syntax_error() {
        assertThatThrownBy(() -> ContentDecoder.decode("|414|"))
                .isInstanceOf(Rejection.class).hasMessageContaining("not a hex byte");
    }

    @Test
    void unknown_escape_is_rejected_not_guessed() {
        assertThatThrownBy(() -> ContentDecoder.decode("a\\nb"))
                .isInstanceOf(Rejection.class).hasMessageContaining("unknown escape");
    }

    @Test
    void trailing_backslash_is_a_syntax_error() {
        assertThatThrownBy(() -> ContentDecoder.decode("abc\\"))
                .isInstanceOf(Rejection.class).hasMessageContaining("lone backslash");
    }

    @Test
    void non_ascii_text_is_rejected_with_advice_to_use_hex() {
        assertThatThrownBy(() -> ContentDecoder.decode("café"))
                .isInstanceOf(Rejection.class).hasMessageContaining("|hex|");
    }

    @Test
    void empty_content_is_a_syntax_error() {
        assertThatThrownBy(() -> ContentDecoder.decode("")).isInstanceOf(Rejection.class);
        assertThatThrownBy(() -> ContentDecoder.decode("||")).isInstanceOf(Rejection.class);
    }
}
