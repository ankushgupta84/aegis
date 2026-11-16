package io.aegis.http;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class UriNormalizerTest {

    @Test
    void plainPathIsUnchanged() {
        assertThat(UriNormalizer.normalize("/a/b.html")).isEqualTo("/a/b.html");
    }

    @Test
    void percentEscapesAreDecodedOnce() {
        assertThat(UriNormalizer.normalize("/a%20b%2Fc")).isEqualTo("/a b/c");
    }

    @Test
    void hexDigitsMayBeEitherCase() {
        assertThat(UriNormalizer.normalize("/%4a%4A")).isEqualTo("/JJ");
    }

    @Test
    void doubleEncodedTargetIsDecodedOnlyOnce() {
        assertThat(UriNormalizer.normalize("/%2527")).isEqualTo("/%27");
        assertThat(UriNormalizer.normalize("/?q=%2527")).isEqualTo("/?q=%27");
    }

    @Test
    void invalidPercentSequencesAreKept() {
        assertThat(UriNormalizer.normalize("/a%zzb")).isEqualTo("/a%zzb");
        assertThat(UriNormalizer.normalize("/a%4")).isEqualTo("/a%4");
        assertThat(UriNormalizer.normalize("/a%")).isEqualTo("/a%");
        assertThat(UriNormalizer.normalize("/a%4g")).isEqualTo("/a%4g");
    }

    @Test
    void percentZeroZeroDecodesToNulByte() {
        assertThat(UriNormalizer.normalize("/a%00b")).isEqualTo("/a\0b");
    }

    @Test
    void repeatedSlashesCollapseIncludingEncodedOnes() {
        assertThat(UriNormalizer.normalize("//a///b")).isEqualTo("/a/b");
        assertThat(UriNormalizer.normalize("/a%2f%2fb")).isEqualTo("/a/b");
    }

    @Test
    void dotSegmentsAreNotResolved() {
        assertThat(UriNormalizer.normalize("/a/../b/./c")).isEqualTo("/a/../b/./c");
        assertThat(UriNormalizer.normalize("/%2e%2e/etc/passwd")).isEqualTo("/../etc/passwd");
    }

    @Test
    void plusIsNotTurnedIntoSpace() {
        assertThat(UriNormalizer.normalize("/a+b?q=c+d")).isEqualTo("/a+b?q=c+d");
    }

    @Test
    void queryIsDecodedButItsSlashesAreKept() {
        assertThat(UriNormalizer.normalize("/p?u=http%3A//x//y")).isEqualTo("/p?u=http://x//y");
    }

    @Test
    void emptyQueryKeepsItsQuestionMark() {
        assertThat(UriNormalizer.normalize("/p?")).isEqualTo("/p?");
    }

    @Test
    void onlyTheFirstQuestionMarkStartsTheQuery() {
        assertThat(UriNormalizer.normalize("/p?a=1?b=2")).isEqualTo("/p?a=1?b=2");
    }

    @Test
    void encodedQuestionMarkStaysInThePath() {
        assertThat(UriNormalizer.normalize("/p%3Fa")).isEqualTo("/p?a");
        assertThat(UriNormalizer.normalizePath("/p%3Fa")).isEqualTo("/p?a");
    }

    @Test
    void highBytesSurviveAsSingleChars() {
        assertThat(UriNormalizer.normalize("/%C3%A9")).isEqualTo("/Ã©");
    }
}
