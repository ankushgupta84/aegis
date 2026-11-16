package io.aegis.waf;

import static io.aegis.rules.Transform.COMPRESS_WHITESPACE;
import static io.aegis.rules.Transform.STRIP_WHITESPACE;
import static io.aegis.rules.Transform.TO_LOWERCASE;
import static io.aegis.rules.Transform.URL_DECODE;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class ViewTransformsTest {

    @Test
    void urlDecodeTurnsPercentEscapesIntoBytesAndPlusIntoSpace() {
        assertThat(ViewTransforms.apply("a%20b+c%41", List.of(URL_DECODE))).isEqualTo("a b cA");
    }

    @Test
    void urlDecodeDecodesOnlyOnce() {
        assertThat(ViewTransforms.apply("%2541", List.of(URL_DECODE))).isEqualTo("%41");
    }

    @Test
    void urlDecodeKeepsInvalidSequences() {
        assertThat(ViewTransforms.apply("%zz%4%", List.of(URL_DECODE))).isEqualTo("%zz%4%");
    }

    @Test
    void urlDecodeDecodesAnEscapeAtTheVeryEnd() {
        assertThat(ViewTransforms.apply("x%7e", List.of(URL_DECODE))).isEqualTo("x~");
    }

    @Test
    void urlDecodeYieldsHighBytesAsSingleChars() {
        assertThat(ViewTransforms.apply("%ff%00", List.of(URL_DECODE))).isEqualTo("ÿ\u0000");
    }

    @Test
    void toLowercaseFoldsAsciiOnly() {
        assertThat(ViewTransforms.apply("AbCÉ", List.of(TO_LOWERCASE))).isEqualTo("abcÉ");
    }

    @Test
    void compressWhitespaceCollapsesEachRunIntoOneSpace() {
        assertThat(ViewTransforms.apply("a \t\r\n b\nc", List.of(COMPRESS_WHITESPACE))).isEqualTo("a b c");
    }

    @Test
    void compressWhitespaceReplacesALoneNewlineWithASpace() {
        assertThat(ViewTransforms.apply("a\nb", List.of(COMPRESS_WHITESPACE))).isEqualTo("a b");
    }

    @Test
    void stripWhitespaceRemovesAllWhitespace() {
        assertThat(ViewTransforms.apply(" s e\tl\n", List.of(STRIP_WHITESPACE))).isEqualTo("sel");
    }

    @Test
    void transformsApplyInTheListedOrder() {
        assertThat(ViewTransforms.apply("%53 E", List.of(URL_DECODE, TO_LOWERCASE, STRIP_WHITESPACE))).isEqualTo("se");
    }

    @Test
    void anUntouchedTextIsReturnedAsIs() {
        String text = "plain";

        assertThat(ViewTransforms.apply(text, List.of(URL_DECODE, TO_LOWERCASE, STRIP_WHITESPACE))).isSameAs(text);
    }
}
