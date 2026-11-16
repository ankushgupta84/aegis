package io.aegis.rules;

import static org.assertj.core.api.Assertions.assertThat;

import io.aegis.http.RuleBuffer;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** Runs the parser over a file written in the style of ET Open and checks what became of each rule. */
class SampleRulesTest {

    private static Path file;
    private static RuleSet set;
    private static Map<Integer, ClassifiedRule> bySid;

    @BeforeAll
    static void parseSampleFile() throws IOException, URISyntaxException {
        file = Paths.get(SampleRulesTest.class.getResource("/rules/sample.rules").toURI());
        set = SuricataRuleParser.parseFile("sample", file);
        bySid = set.rules().stream().filter(r -> r.sid() != 0)
                .collect(Collectors.toMap(ClassifiedRule::sid, Function.identity()));
    }

    private static ClassifiedRule rule(int sid) {
        return bySid.get(sid);
    }

    private static void assertUnsupported(int sid, String reasonPart) {
        assertThat(rule(sid).status()).as("sid %d: %s", sid, rule(sid).reason()).isEqualTo(RuleStatus.UNSUPPORTED);
        assertThat(rule(sid).reason()).contains(reasonPart);
    }

    private static void assertNotApplicable(int sid, String reasonPart) {
        assertThat(rule(sid).status()).as("sid %d", sid).isEqualTo(RuleStatus.NOT_APPLICABLE);
        assertThat(rule(sid).reason()).contains(reasonPart);
    }

    private static List<Condition> conditions(int sid) {
        assertThat(rule(sid).status()).as("sid %d: %s", sid, rule(sid).reason()).isEqualTo(RuleStatus.ACTIVE);
        return rule(sid).rule().conditions();
    }

    @Test
    void file_is_accepted_whole_and_every_rule_line_yields_one_result() {
        assertThat(set.rules()).hasSize(70);
        assertThat(set.count(RuleStatus.ACTIVE)).isEqualTo(29);
        assertThat(set.count(RuleStatus.NOT_APPLICABLE)).isEqualTo(10);
        assertThat(set.count(RuleStatus.UNSUPPORTED)).isEqualTo(31);
    }

    @Test
    void commented_out_rule_is_not_counted() {
        assertThat(bySid).doesNotContainKey(9000099);
    }

    @Test
    void every_active_rule_has_conditions_and_every_skipped_rule_a_reason() {
        for (ClassifiedRule result : set.rules()) {
            if (result.status() == RuleStatus.ACTIVE) {
                assertThat(result.rule().conditions()).isNotEmpty();
                assertThat(result.reason()).isEmpty();
            } else {
                assertThat(result.reason()).as("sid %d", result.sid()).isNotBlank();
            }
        }
    }

    @Test
    void raw_of_every_single_line_rule_matches_its_line_in_the_file() throws IOException {
        List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        for (ClassifiedRule result : set.rules()) {
            if (!result.raw().contains("\n")) {
                assertThat(lines).contains(result.raw());
            }
        }
    }

    @Test
    void log4j_rule_decodes_hex_and_scores_critical_attack() {
        ContentMatch match = (ContentMatch) conditions(9000001).get(0);
        assertThat(match.buffer()).isEqualTo(RuleBuffer.HTTP_URI);
        assertThat(match.pattern()).isEqualTo("${jndi:");
        assertThat(match.nocase()).isTrue();
        assertThat(match.fastPattern()).isTrue();
        assertThat(rule(9000001).rule().defaultScore()).isEqualTo(5);
        assertThat(rule(9000001).rev()).isEqualTo(3);
        assertThat(rule(9000001).rule().references()).containsExactly("cve,2021-44228");
        assertThat(rule(9000001).rule().metadata()).containsEntry("signature_severity", List.of("Critical"));
    }

    @Test
    void sql_injection_rule_mixes_relative_content_and_a_flagged_pcre() {
        List<Condition> conditions = conditions(9000002);
        assertThat(conditions).hasSize(3);
        ContentMatch select = (ContentMatch) conditions.get(1);
        assertThat(select.distance()).hasValue(0);
        assertThat(select.within()).hasValue(20);
        PcreMatch pcre = (PcreMatch) conditions.get(2);
        assertThat(pcre.buffer()).isEqualTo(RuleBuffer.HTTP_URI);
        assertThat(pcre.caseInsensitive()).isTrue();
    }

    @Test
    void each_sticky_buffer_rule_lands_on_its_buffer() {
        assertThat(conditions(9000003).get(0).buffer()).isEqualTo(RuleBuffer.HTTP_USER_AGENT);
        assertThat(conditions(9000004).get(0).buffer()).isEqualTo(RuleBuffer.HTTP_COOKIE);
        assertThat(conditions(9000005).get(0).buffer()).isEqualTo(RuleBuffer.HTTP_HOST);
        assertThat(conditions(9000006)).extracting(Condition::buffer)
                .containsExactly(RuleBuffer.HTTP_CONTENT_TYPE, RuleBuffer.HTTP_REQUEST_BODY);
        assertThat(conditions(9000007).get(0).buffer()).isEqualTo(RuleBuffer.HTTP_REQUEST_LINE);
        assertThat(conditions(9000008).get(0).buffer()).isEqualTo(RuleBuffer.HTTP_URI_RAW);
        assertThat(conditions(9000009).get(0).buffer()).isEqualTo(RuleBuffer.HTTP_METHOD);
    }

    @Test
    void request_line_rule_keeps_both_anchors() {
        ContentMatch match = (ContentMatch) conditions(9000007).get(0);
        assertThat(match.startsWith()).isTrue();
        assertThat(match.endsWith()).isTrue();
    }

    @Test
    void transforms_in_the_sample_apply_in_order() {
        assertThat(conditions(9000010).get(0).transforms()).containsExactly(Transform.URL_DECODE, Transform.TO_LOWERCASE);
        assertThat(conditions(9000011).get(0).transforms()).containsExactly(Transform.COMPRESS_WHITESPACE);
    }

    @Test
    void hex_crlf_in_a_header_rule_decodes_to_bytes() {
        ContentMatch match = (ContentMatch) conditions(9000012).get(0);
        assertThat(match.pattern()).isEqualTo("\r\nContent-Length: 0\r\n");
        assertThat(match.fastPattern()).isTrue();
    }

    @Test
    void legacy_modifiers_bind_each_content_to_its_own_buffer() {
        assertThat(conditions(9000020)).extracting(Condition::buffer)
                .containsExactly(RuleBuffer.HTTP_METHOD, RuleBuffer.HTTP_URI, RuleBuffer.HTTP_REQUEST_BODY);
        assertThat(conditions(9000021)).extracting(Condition::buffer)
                .containsExactly(RuleBuffer.HTTP_USER_AGENT, RuleBuffer.HTTP_USER_AGENT);
        assertThat(conditions(9000022)).extracting(Condition::buffer).containsExactly(RuleBuffer.HTTP_COOKIE,
                RuleBuffer.HTTP_HOST, RuleBuffer.HTTP_CONTENT_TYPE, RuleBuffer.HTTP_URI_RAW, RuleBuffer.HTTP_HEADER);
        assertThat(((ContentMatch) conditions(9000020).get(1)).nocase()).isTrue();
    }

    @Test
    void sticky_buffer_persists_around_a_legacy_modifier() {
        assertThat(conditions(9000023)).extracting(Condition::buffer)
                .containsExactly(RuleBuffer.HTTP_URI, RuleBuffer.HTTP_HEADER, RuleBuffer.HTTP_URI);
    }

    @Test
    void pcre_flags_choose_buffers_and_modes() {
        assertThat(conditions(9000030).get(0).buffer()).isEqualTo(RuleBuffer.HTTP_URI);
        PcreMatch body = (PcreMatch) conditions(9000031).get(0);
        assertThat(body.buffer()).isEqualTo(RuleBuffer.HTTP_REQUEST_BODY);
        assertThat(body.dotAll()).isTrue();
        assertThat(body.multiline()).isTrue();
        PcreMatch negated = (PcreMatch) conditions(9000032).get(1);
        assertThat(negated.negated()).isTrue();
        assertThat(negated.relative()).isTrue();
        assertThat(negated.buffer()).isEqualTo(RuleBuffer.HTTP_URI);
        assertThat(conditions(9000033)).extracting(Condition::buffer).containsExactly(RuleBuffer.HTTP_HEADER,
                RuleBuffer.HTTP_USER_AGENT, RuleBuffer.HTTP_HOST, RuleBuffer.HTTP_METHOD, RuleBuffer.HTTP_COOKIE,
                RuleBuffer.HTTP_URI_RAW);
    }

    @Test
    void semicolon_and_escaped_quote_inside_pcre_survive() {
        assertThat(((PcreMatch) conditions(9000034).get(0)).regex()).isEqualTo("a;b\\\"c[;]");
    }

    @Test
    void escapes_in_content_and_msg_decode_exactly() {
        assertThat(rule(9000040).rule().msg()).isEqualTo("ET WEB_SERVER Escaped \"quote\" and semicolon; in msg");
        assertThat(((ContentMatch) conditions(9000040).get(0)).pattern()).isEqualTo("a;b\"c\\d|e");
    }

    @Test
    void header_with_variables_and_bracketed_lists_parses() {
        assertThat(rule(9000041).status()).isEqualTo(RuleStatus.ACTIVE);
    }

    @Test
    void multi_line_rule_parses_and_keeps_its_original_lines() {
        assertThat(conditions(9000042)).hasSize(2);
        assertThat(rule(9000042).raw()).startsWith("alert http any any -> any any (msg:\"ET WEB_SERVER Multi-line rule\"; \\\n    flow:");
        assertThat(rule(9000042).raw().lines().count()).isEqualTo(5);
    }

    @Test
    void scores_follow_override_priority_and_classtype() {
        assertThat(rule(9000043).rule().defaultScore()).as("explicit score").isEqualTo(42);
        assertThat(rule(9000044).rule().defaultScore()).as("misc at priority 1").isEqualTo(1);
        assertThat(rule(9000045).rule().defaultScore()).as("unknown classtype").isZero();
        assertThat(rule(9000003).rule().defaultScore()).as("attack, Minor").isEqualTo(3);
        assertThat(rule(9000004).rule().defaultScore()).as("policy, priority 1").isEqualTo(2);
        assertThat(rule(9000007).rule().defaultScore()).as("recon, default priority 2").isEqualTo(2);
        assertThat(rule(9000012).rule().defaultScore()).as("misc, priority 2").isZero();
    }

    @Test
    void negated_content_and_repeated_references_are_recorded() {
        assertThat(((ContentMatch) conditions(9000046).get(0)).negated()).isTrue();
        assertThat(rule(9000046).rule().references()).containsExactly("url,example.com/a", "cve,2020-1234", "cve,2020-9999");
        assertThat(rule(9000046).rev()).isEqualTo(7);
    }

    @Test
    void drop_action_is_kept_on_the_rule() {
        assertThat(rule(9000047).rule().action()).isEqualTo("drop");
    }

    @Test
    void other_protocols_and_raw_payload_rules_are_not_applicable() {
        for (int sid = 9000050; sid <= 9000056; sid++) {
            assertNotApplicable(sid, "carries traffic Aegis never sees");
        }
        assertNotApplicable(9000057, "matches raw TCP payload; Aegis inspects decoded HTTP");
        assertNotApplicable(9000058, "matches raw TCP payload; Aegis inspects decoded HTTP");
    }

    @Test
    void raw_payload_wins_over_an_unsupported_keyword_in_the_same_rule() {
        assertNotApplicable(9000059, "matches raw TCP payload");
    }

    @Test
    void rules_with_unsupported_keywords_name_the_keyword() {
        String[] keywords = {"flowbits", "threshold", "detection_filter", "byte_test", "byte_jump", "byte_extract",
                "isdataat", "urilen", "bsize", "dsize", "xbits", "lua", "http.header_names", "http.accept", "http.referer"};
        for (int i = 0; i < keywords.length; i++) {
            assertUnsupported(9000060 + i, "'" + keywords[i] + "'");
        }
    }

    @Test
    void response_rules_are_unsupported_because_aegis_does_not_inspect_responses() {
        for (int sid = 9000075; sid <= 9000078; sid++) {
            assertUnsupported(sid, "inspects responses, which Aegis does not inspect yet");
        }
    }

    @Test
    void pcre_rules_needing_backtracking_are_unsupported() {
        for (int sid = 9000079; sid <= 9000081; sid++) {
            assertUnsupported(sid, "pcre needs a feature a linear-time engine cannot provide");
        }
        assertUnsupported(9000082, "pcre flag 'A'");
    }

    @Test
    void remaining_unsupported_causes_are_reported_plainly() {
        assertUnsupported(9000083, "no inspectable condition");
        assertUnsupported(9000084, "score");
        assertUnsupported(9000085, "'future_keyword'");
        assertUnsupported(9000065, "byte_extract");
    }

    @Test
    void unparseable_lines_are_unsupported_syntax_errors() {
        List<ClassifiedRule> garbage = set.rules().stream().filter(r -> r.reason().startsWith("syntax error")).toList();
        assertThat(garbage).extracting(ClassifiedRule::raw).contains("this is not a rule at all");
        assertThat(garbage).allMatch(r -> r.status() == RuleStatus.UNSUPPORTED);
        assertThat(rule(9000090).reason()).startsWith("syntax error");
        assertThat(garbage).filteredOn(r -> r.sid() == 0).hasSize(4);
    }

    @Test
    void active_rules_count_matches_the_rule_set_view() {
        assertThat(set.activeRules()).hasSize((int) set.count(RuleStatus.ACTIVE));
    }
}
