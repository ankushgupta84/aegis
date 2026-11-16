package io.aegis.rules;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.Map;
import java.util.OptionalInt;
import org.junit.jupiter.api.Test;

class ScoreTableTest {

    private static final OptionalInt NO_PRIORITY = OptionalInt.empty();

    private static int score(String classtype, OptionalInt priority, Map<String, List<String>> metadata) {
        return ScoreTable.defaultScore(classtype, priority, metadata);
    }

    private static Map<String, List<String>> severity(String name) {
        return Map.of("signature_severity", List.of(name));
    }

    @Test
    void attack_scores_follow_the_published_row_for_each_severity() {
        assertThat(score("web-application-attack", NO_PRIORITY, severity("Critical"))).isEqualTo(5);
        assertThat(score("web-application-attack", NO_PRIORITY, severity("Major"))).isEqualTo(5);
        assertThat(score("web-application-attack", NO_PRIORITY, severity("Minor"))).isEqualTo(3);
        assertThat(score("web-application-attack", NO_PRIORITY, severity("Informational"))).isEqualTo(1);
    }

    @Test
    void recon_scores_follow_the_published_row() {
        assertThat(score("attempted-recon", NO_PRIORITY, severity("Critical"))).isEqualTo(3);
        assertThat(score("attempted-recon", NO_PRIORITY, severity("Major"))).isEqualTo(3);
        assertThat(score("attempted-recon", NO_PRIORITY, severity("Minor"))).isEqualTo(2);
        assertThat(score("attempted-recon", NO_PRIORITY, severity("Informational"))).isZero();
    }

    @Test
    void policy_scores_follow_the_published_row() {
        assertThat(score("policy-violation", NO_PRIORITY, severity("Critical"))).isEqualTo(2);
        assertThat(score("policy-violation", NO_PRIORITY, severity("Major"))).isEqualTo(2);
        assertThat(score("policy-violation", NO_PRIORITY, severity("Minor"))).isEqualTo(1);
        assertThat(score("policy-violation", NO_PRIORITY, severity("Informational"))).isZero();
    }

    @Test
    void misc_scores_follow_the_published_row() {
        assertThat(score("misc-activity", NO_PRIORITY, severity("Critical"))).isEqualTo(1);
        assertThat(score("misc-activity", NO_PRIORITY, severity("Major"))).isEqualTo(1);
        assertThat(score("misc-activity", NO_PRIORITY, severity("Minor"))).isZero();
        assertThat(score("misc-activity", NO_PRIORITY, severity("Informational"))).isZero();
    }

    @Test
    void severity_name_ignores_case() {
        assertThat(score("trojan-activity", NO_PRIORITY, severity("critical"))).isEqualTo(5);
    }

    @Test
    void severity_metadata_beats_rule_priority() {
        assertThat(score("trojan-activity", OptionalInt.of(3), severity("Critical"))).isEqualTo(5);
    }

    @Test
    void rule_priority_maps_one_to_major_two_to_minor_and_three_or_four_to_informational() {
        assertThat(score("trojan-activity", OptionalInt.of(1), Map.of())).isEqualTo(5);
        assertThat(score("trojan-activity", OptionalInt.of(2), Map.of())).isEqualTo(3);
        assertThat(score("trojan-activity", OptionalInt.of(3), Map.of())).isEqualTo(1);
        assertThat(score("trojan-activity", OptionalInt.of(4), Map.of())).isEqualTo(1);
        assertThat(score("trojan-activity", OptionalInt.of(200), Map.of())).isEqualTo(1);
    }

    @Test
    void classtype_default_priority_is_used_when_the_rule_has_none() {
        assertThat(score("trojan-activity", NO_PRIORITY, Map.of())).isEqualTo(5);
        assertThat(score("attempted-dos", NO_PRIORITY, Map.of())).isEqualTo(3);
        assertThat(score("network-scan", NO_PRIORITY, Map.of())).isZero();
        assertThat(score("tcp-connection", NO_PRIORITY, Map.of())).isZero();
    }

    @Test
    void unknown_or_missing_classtype_is_misc_at_priority_three() {
        assertThat(score("made-up", NO_PRIORITY, Map.of())).isZero();
        assertThat(score("", NO_PRIORITY, Map.of())).isZero();
        assertThat(score("made-up", OptionalInt.of(1), Map.of())).isEqualTo(1);
        assertThat(score("made-up", NO_PRIORITY, severity("Critical"))).isEqualTo(1);
    }

    @Test
    void explicit_score_wins_over_everything() {
        Map<String, List<String>> metadata = Map.of("score", List.of("42"), "signature_severity", List.of("Critical"));
        assertThat(score("trojan-activity", OptionalInt.of(1), metadata)).isEqualTo(42);
    }

    @Test
    void explicit_score_accepts_the_limits_zero_and_one_hundred() {
        assertThat(score("x", NO_PRIORITY, Map.of("score", List.of("0")))).isZero();
        assertThat(score("x", NO_PRIORITY, Map.of("score", List.of("100")))).isEqualTo(100);
    }

    @Test
    void explicit_score_outside_zero_to_one_hundred_is_rejected() {
        assertThatThrownBy(() -> score("x", NO_PRIORITY, Map.of("score", List.of("101"))))
                .isInstanceOf(Rejection.class).hasMessageContaining("'101'");
        assertThatThrownBy(() -> score("x", NO_PRIORITY, Map.of("score", List.of("-1")))).isInstanceOf(Rejection.class);
    }

    @Test
    void explicit_score_that_is_not_a_number_is_rejected() {
        assertThatThrownBy(() -> score("x", NO_PRIORITY, Map.of("score", List.of("high"))))
                .isInstanceOf(Rejection.class).hasMessageContaining("'high'");
    }

    @Test
    void severity_unknown_means_unrated_so_priority_decides() {
        assertThat(score("web-application-attack", OptionalInt.of(1), severity("Unknown"))).isEqualTo(5);
        assertThat(score("web-application-attack", OptionalInt.of(2), severity("unknown"))).isEqualTo(3);
    }

    @Test
    void unknown_severity_name_is_rejected_rather_than_guessed() {
        assertThatThrownBy(() -> score("trojan-activity", NO_PRIORITY, severity("Severe")))
                .isInstanceOf(Rejection.class).hasMessageContaining("'Severe'");
    }

    @Test
    void every_stock_classtype_named_in_the_brief_has_the_expected_category() {
        assertThat(Classtypes.find("web-application-attack")).get().extracting(Classtypes.Entry::category).isEqualTo(Category.ATTACK);
        assertThat(Classtypes.find("attempted-admin")).get().extracting(Classtypes.Entry::category).isEqualTo(Category.ATTACK);
        assertThat(Classtypes.find("attempted-user")).get().extracting(Classtypes.Entry::category).isEqualTo(Category.ATTACK);
        assertThat(Classtypes.find("trojan-activity")).get().extracting(Classtypes.Entry::category).isEqualTo(Category.ATTACK);
        assertThat(Classtypes.find("shellcode-detect")).get().extracting(Classtypes.Entry::category).isEqualTo(Category.ATTACK);
        assertThat(Classtypes.find("exploit-kit")).get().extracting(Classtypes.Entry::category).isEqualTo(Category.ATTACK);
        assertThat(Classtypes.find("command-and-control")).get().extracting(Classtypes.Entry::category).isEqualTo(Category.ATTACK);
        assertThat(Classtypes.find("attempted-recon")).get().extracting(Classtypes.Entry::category).isEqualTo(Category.RECON);
        assertThat(Classtypes.find("network-scan")).get().extracting(Classtypes.Entry::category).isEqualTo(Category.RECON);
        assertThat(Classtypes.find("successful-recon-limited")).get().extracting(Classtypes.Entry::category).isEqualTo(Category.RECON);
        assertThat(Classtypes.find("successful-recon-largescale")).get().extracting(Classtypes.Entry::category).isEqualTo(Category.RECON);
        assertThat(Classtypes.find("policy-violation")).get().extracting(Classtypes.Entry::category).isEqualTo(Category.POLICY);
        assertThat(Classtypes.find("inappropriate-content")).get().extracting(Classtypes.Entry::category).isEqualTo(Category.POLICY);
        assertThat(Classtypes.find("no-such-class")).isEmpty();
    }
}
