package io.aegis.waf;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

class AhoCorasickTest {

    private static List<Integer> scan(AhoCorasick automaton, String text) {
        List<Integer> found = new ArrayList<>();
        automaton.scan(text, found::add);
        return found;
    }

    private static TreeSet<Integer> distinctIds(AhoCorasick automaton, String text) {
        return new TreeSet<>(scan(automaton, text));
    }

    @Test
    void findsEachPatternWhereverItOccurs() {
        AhoCorasick automaton = new AhoCorasick(List.of("select", "union"));

        assertThat(scan(automaton, "x union y select z")).containsExactly(1, 0);
    }

    @Test
    void reportsOverlappingPatterns() {
        AhoCorasick automaton = new AhoCorasick(List.of("abab", "baba"));

        assertThat(scan(automaton, "ababa")).containsExactly(0, 1);
    }

    @Test
    void reportsAPatternThatIsASuffixOfAnotherAtTheSamePosition() {
        AhoCorasick automaton = new AhoCorasick(List.of("she", "he", "e"));

        assertThat(scan(automaton, "she")).containsExactlyInAnyOrder(0, 1, 2);
    }

    @Test
    void reportsAPatternThatIsAPrefixOfAnother() {
        AhoCorasick automaton = new AhoCorasick(List.of("pass", "password"));

        assertThat(scan(automaton, "password")).containsExactly(0, 1);
    }

    @Test
    void reportsEveryOccurrenceOfARepeatedPatternInText() {
        AhoCorasick automaton = new AhoCorasick(List.of("aa"));

        assertThat(scan(automaton, "aaaa")).hasSize(3);
    }

    @Test
    void reportsEachDuplicatedPatternUnderItsOwnId() {
        AhoCorasick automaton = new AhoCorasick(List.of("cmd.exe", "other", "cmd.exe"));

        assertThat(scan(automaton, "run cmd.exe")).containsExactlyInAnyOrder(0, 2);
    }

    @Test
    void foldsAsciiCaseInPatternsAndText() {
        AhoCorasick automaton = new AhoCorasick(List.of("SeLeCt"));

        assertThat(scan(automaton, "xx SELECT xx")).containsExactly(0);
        assertThat(scan(automaton, "select")).containsExactly(0);
    }

    @Test
    void doesNotFoldLatin1Letters() {
        AhoCorasick automaton = new AhoCorasick(List.of("é"));

        assertThat(scan(automaton, "É")).isEmpty();
    }

    @Test
    void handlesEveryByteValueInPatternsAndText() {
        StringBuilder allBytes = new StringBuilder();
        for (char c = 0; c <= 0xFF; c++) {
            allBytes.append(c);
        }
        AhoCorasick automaton = new AhoCorasick(List.of("\u0000\u0001", "þÿ", "\u0080\u0081\u0082"));

        assertThat(distinctIds(automaton, allBytes.toString())).containsExactly(0, 1, 2);
    }

    @Test
    void bytesInNoPatternResetTheMatch() {
        AhoCorasick automaton = new AhoCorasick(List.of("ab"));

        assertThat(scan(automaton, "a\u0000b")).isEmpty();
        assertThat(scan(automaton, "a\u0000ab")).containsExactly(0);
    }

    @Test
    void groupsBytesIntoClassesSoTheTableIsNarrow() {
        AhoCorasick automaton = new AhoCorasick(List.of("ab", "ba"));

        assertThat(automaton.classCount()).isEqualTo(3);
        assertThat(automaton.stateCount()).isEqualTo(5);
    }

    @Test
    void scanningEmptyTextFindsNothing() {
        assertThat(scan(new AhoCorasick(List.of("a")), "")).isEmpty();
    }

    @Test
    void anAutomatonWithoutPatternsFindsNothing() {
        assertThat(scan(new AhoCorasick(List.of()), "anything")).isEmpty();
    }

    @Test
    void rejectsAnEmptyPattern() {
        assertThatThrownBy(() -> new AhoCorasick(List.of("ok", "")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("empty");
    }

    @Test
    void rejectsAPatternCharThatIsNotAByte() {
        assertThatThrownBy(() -> new AhoCorasick(List.of("Ā")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("0100");
    }
}
