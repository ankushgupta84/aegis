package io.aegis.rules;

import static io.aegis.rules.TestRules.active;
import static io.aegis.rules.TestRules.classify;
import static io.aegis.rules.TestRules.http;
import static io.aegis.rules.TestRules.parse;
import static org.assertj.core.api.Assertions.assertThat;

import io.aegis.http.RuleBuffer;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.OptionalInt;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SuricataRuleParserTest {

    private static ContentMatch content(SuricataRule rule, int index) {
        return (ContentMatch) rule.conditions().get(index);
    }

    private static PcreMatch pcre(SuricataRule rule, int index) {
        return (PcreMatch) rule.conditions().get(index);
    }

    private static void assertUnsupported(String options, String reasonPart) {
        ClassifiedRule result = http(options);
        assertThat(result.status()).as(result.reason()).isEqualTo(RuleStatus.UNSUPPORTED);
        assertThat(result.reason()).contains(reasonPart);
        assertThat(result.rule()).isNull();
    }

    // ---- file structure -------------------------------------------------------

    @Test
    void blank_lines_and_comments_are_skipped_and_not_counted() {
        RuleSet set = parse("""

                # a comment
                   # an indented comment
                #alert http any any -> any any (http.uri; content:"x"; sid:1;)
                alert http any any -> any any (http.uri; content:"x"; sid:2;)

                """);
        assertThat(set.rules()).extracting(ClassifiedRule::sid).containsExactly(2);
    }

    @Test
    void empty_file_gives_an_empty_rule_set() {
        assertThat(parse("").rules()).isEmpty();
    }

    @Test
    void rule_set_keeps_its_name() {
        assertThat(parse("").name()).isEqualTo("test");
    }

    @Test
    void trailing_backslash_continues_the_rule_on_the_next_line() {
        ClassifiedRule result = classify("alert http any any -> any any (msg:\"split\"; \\\n   http.uri; \\\n content:\"/a\"; sid:7;)");
        assertThat(result.status()).isEqualTo(RuleStatus.ACTIVE);
        assertThat(result.rule().msg()).isEqualTo("split");
        assertThat(content(result.rule(), 0).buffer()).isEqualTo(RuleBuffer.HTTP_URI);
    }

    @Test
    void raw_keeps_every_line_of_a_continued_rule_byte_for_byte() {
        String raw = "alert http any any -> any any (msg:\"split\"; \\\n   http.uri; \\\n content:\"/a\"; sid:7;)";
        assertThat(classify(raw).raw()).isEqualTo(raw);
    }

    @Test
    void raw_of_an_active_rule_is_the_line_exactly_as_written_including_odd_spacing() {
        String raw = "alert  http any any -> any any ( msg:\"x\" ;  http.uri;content:\"/a\";   sid:1; )";
        ClassifiedRule result = classify(raw);
        assertThat(result.status()).isEqualTo(RuleStatus.ACTIVE);
        assertThat(result.raw()).isEqualTo(raw);
        assertThat(result.rule().raw()).isEqualTo(raw);
    }

    @Test
    void raw_of_skipped_and_garbage_rules_is_preserved_too() {
        String garbage = "  this is not a rule  ";
        String dns = "alert dns any any -> any any (dns.query; content:\"x\"; sid:3;)";
        assertThat(parse(garbage + "\n" + dns).rules()).extracting(ClassifiedRule::raw).containsExactly(garbage, dns);
    }

    @Test
    void continuation_at_end_of_file_still_yields_the_rule() {
        ClassifiedRule result = classify("alert http any any -> any any (http.uri; content:\"/a\"; sid:7;) \\");
        assertThat(result.sid()).isEqualTo(7);
    }

    @Test
    void windows_line_endings_are_handled() {
        RuleSet set = parse("alert http any any -> any any (http.uri; content:\"/a\"; sid:1;)\r\n"
                + "alert http any any -> any any (http.uri; content:\"/b\"; sid:2;)\r\n");
        assertThat(set.count(RuleStatus.ACTIVE)).isEqualTo(2);
    }

    @Test
    void parse_file_reads_utf8_and_survives_invalid_bytes(@TempDir Path dir) throws IOException {
        Path file = dir.resolve("bad.rules");
        byte[] head = "alert http any any -> any any (msg:\"bad ".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] tail = "\"; http.uri; content:\"/a\"; sid:1;)\n".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        byte[] bytes = new byte[head.length + 1 + tail.length];
        System.arraycopy(head, 0, bytes, 0, head.length);
        bytes[head.length] = (byte) 0xff;
        System.arraycopy(tail, 0, bytes, head.length + 1, tail.length);
        Files.write(file, bytes);

        RuleSet set = SuricataRuleParser.parseFile("bad", file);

        assertThat(set.count(RuleStatus.ACTIVE)).isEqualTo(1);
    }

    // ---- active rule contents -------------------------------------------------

    @Test
    void recorded_fields_are_taken_from_the_options() {
        SuricataRule rule = active("msg:\"ET TEST hello\"; http.uri; content:\"/a\"; classtype:web-application-attack; "
                + "sid:12; rev:4; reference:cve,2021-1; reference:url,x.org/y; "
                + "metadata:a one, b two, a three; metadata:c four; gid:1; target:dest_ip;");
        assertThat(rule.sid()).isEqualTo(12);
        assertThat(rule.rev()).isEqualTo(4);
        assertThat(rule.action()).isEqualTo("alert");
        assertThat(rule.msg()).isEqualTo("ET TEST hello");
        assertThat(rule.classtype()).isEqualTo("web-application-attack");
        assertThat(rule.references()).containsExactly("cve,2021-1", "url,x.org/y");
        assertThat(rule.metadata()).containsEntry("a", List.of("one", "three")).containsEntry("b", List.of("two"))
                .containsEntry("c", List.of("four"));
    }

    @Test
    void rev_defaults_to_zero_and_classtype_to_empty() {
        SuricataRule rule = active("http.uri; content:\"/a\"; sid:5;");
        assertThat(rule.rev()).isZero();
        assertThat(rule.classtype()).isEmpty();
        assertThat(rule.msg()).isEmpty();
    }

    @Test
    void msg_escapes_are_removed() {
        assertThat(active("msg:\"a \\\"b\\\" \\; c \\\\ d\"; http.uri; content:\"/a\"; sid:1;").msg())
                .isEqualTo("a \"b\" ; c \\ d");
    }

    @Test
    void the_rules_own_action_is_kept() {
        ClassifiedRule drop = classify("drop http any any -> any any (http.uri; content:\"/a\"; sid:1;)");
        assertThat(drop.rule().action()).isEqualTo("drop");
    }

    @Test
    void score_comes_from_the_score_table() {
        assertThat(active("http.uri; content:\"/a\"; classtype:trojan-activity; sid:1;").defaultScore()).isEqualTo(5);
        assertThat(active("http.uri; content:\"/a\"; classtype:trojan-activity; sid:1; metadata:score 9;").defaultScore())
                .isEqualTo(9);
    }

    // ---- content decoding and modifiers ---------------------------------------

    @Test
    void content_hex_and_escapes_are_decoded_in_the_condition() {
        SuricataRule rule = active("http.header; content:\"|0d 0a|Host|3a| a\\;b\\\"c\\\\\"; sid:1;");
        assertThat(content(rule, 0).pattern()).isEqualTo("\r\nHost: a;b\"c\\");
    }

    @Test
    void semicolon_inside_content_does_not_end_the_option() {
        SuricataRule rule = active("http.uri; content:\"a;b\"; nocase; sid:1;");
        assertThat(content(rule, 0).pattern()).isEqualTo("a;b");
        assertThat(content(rule, 0).nocase()).isTrue();
    }

    @Test
    void negated_content_is_marked() {
        SuricataRule rule = active("http.header; content:!\"X-Test\"; sid:1;");
        assertThat(content(rule, 0).negated()).isTrue();
    }

    @Test
    void every_content_modifier_attaches_to_the_content_before_it() {
        SuricataRule rule = active("http.uri; content:\"a\"; nocase; offset:1; depth:10; startswith; endswith; fast_pattern; "
                + "content:\"b\"; distance:-2; within:5; sid:1;");
        ContentMatch first = content(rule, 0);
        assertThat(first.nocase()).isTrue();
        assertThat(first.offset()).hasValue(1);
        assertThat(first.depth()).hasValue(10);
        assertThat(first.startsWith()).isTrue();
        assertThat(first.endsWith()).isTrue();
        assertThat(first.fastPattern()).isTrue();
        assertThat(first.isRelative()).isFalse();
        ContentMatch second = content(rule, 1);
        assertThat(second.nocase()).isFalse();
        assertThat(second.offset()).isEmpty();
        assertThat(second.distance()).hasValue(-2);
        assertThat(second.within()).hasValue(5);
        assertThat(second.isRelative()).isTrue();
        assertThat(second.fastPattern()).isFalse();
    }

    @Test
    void all_fast_pattern_spellings_set_the_flag() {
        assertThat(content(active("http.uri; content:\"a\"; fast_pattern; sid:1;"), 0).fastPattern()).isTrue();
        assertThat(content(active("http.uri; content:\"a\"; fast_pattern:only; sid:1;"), 0).fastPattern()).isTrue();
        assertThat(content(active("http.uri; content:\"a\"; fast_pattern:2,3; sid:1;"), 0).fastPattern()).isTrue();
    }

    @Test
    void modifier_without_a_preceding_content_is_a_syntax_error() {
        assertUnsupported("http.uri; nocase; content:\"a\"; sid:1;", "syntax error: 'nocase' must directly follow a content");
    }

    @Test
    void modifier_after_a_pcre_does_not_reach_back_to_the_earlier_content() {
        assertUnsupported("http.uri; content:\"a\"; pcre:\"/b/\"; nocase; sid:1;", "syntax error");
    }

    @Test
    void modifier_with_a_byte_extract_variable_makes_the_rule_unsupported() {
        assertUnsupported("http.uri; content:\"a\"; depth:mylen; sid:1;", "'depth' value 'mylen'");
        assertUnsupported("http.uri; content:\"a\"; offset:var; sid:1;", "'offset'");
        assertUnsupported("http.uri; content:\"a\"; content:\"b\"; distance:var; sid:1;", "'distance'");
        assertUnsupported("http.uri; content:\"a\"; content:\"b\"; within:var; sid:1;", "'within'");
    }

    @Test
    void empty_content_is_a_syntax_error() {
        assertUnsupported("http.uri; content:\"\"; sid:1;", "syntax error");
    }

    @Test
    void unquoted_content_is_a_syntax_error() {
        assertUnsupported("http.uri; content:abc; sid:1;", "syntax error");
    }

    // ---- buffers ---------------------------------------------------------------

    @Test
    void every_sticky_buffer_selects_its_buffer() {
        for (RuleBuffer buffer : RuleBuffer.values()) {
            SuricataRule rule = active(buffer.stickyKeyword() + "; content:\"a\"; sid:1;");
            assertThat(rule.conditions()).extracting(Condition::buffer).containsExactly(buffer);
        }
    }

    @Test
    void sticky_buffer_persists_for_all_following_conditions_until_the_next_one() {
        SuricataRule rule = active("http.uri; content:\"a\"; pcre:\"/b/\"; content:\"c\"; http.header; content:\"d\"; sid:1;");
        assertThat(rule.conditions()).extracting(Condition::buffer).containsExactly(
                RuleBuffer.HTTP_URI, RuleBuffer.HTTP_URI, RuleBuffer.HTTP_URI, RuleBuffer.HTTP_HEADER);
    }

    @Test
    void every_legacy_modifier_selects_its_buffer() {
        for (RuleBuffer buffer : RuleBuffer.values()) {
            if (buffer.legacyModifier() == null) {
                continue;
            }
            SuricataRule rule = active("content:\"a\"; " + buffer.legacyModifier() + "; sid:1;");
            assertThat(rule.conditions()).extracting(Condition::buffer).containsExactly(buffer);
        }
    }

    @Test
    void legacy_modifier_binds_to_the_preceding_content_only() {
        ClassifiedRule result = http("content:\"a\"; http_uri; content:\"b\"; sid:1;");
        assertThat(result.status()).as("second content has no buffer").isEqualTo(RuleStatus.NOT_APPLICABLE);

        SuricataRule rule = active("content:\"a\"; http_uri; content:\"b\"; http_header; nocase; sid:1;");
        assertThat(content(rule, 0).buffer()).isEqualTo(RuleBuffer.HTTP_URI);
        assertThat(content(rule, 0).nocase()).isFalse();
        assertThat(content(rule, 1).buffer()).isEqualTo(RuleBuffer.HTTP_HEADER);
        assertThat(content(rule, 1).nocase()).isTrue();
    }

    @Test
    void legacy_modifier_overrides_the_sticky_buffer_for_its_content_only() {
        SuricataRule rule = active("http.uri; content:\"a\"; content:\"b\"; http_header; content:\"c\"; sid:1;");
        assertThat(rule.conditions()).extracting(Condition::buffer)
                .containsExactly(RuleBuffer.HTTP_URI, RuleBuffer.HTTP_HEADER, RuleBuffer.HTTP_URI);
    }

    @Test
    void modifiers_may_sit_between_the_content_and_its_legacy_buffer() {
        SuricataRule rule = active("content:\"a\"; nocase; depth:5; http_uri; sid:1;");
        assertThat(content(rule, 0).buffer()).isEqualTo(RuleBuffer.HTTP_URI);
        assertThat(content(rule, 0).nocase()).isTrue();
        assertThat(content(rule, 0).depth()).hasValue(5);
    }

    @Test
    void two_legacy_buffers_on_one_content_are_a_syntax_error() {
        assertUnsupported("content:\"a\"; http_uri; http_header; sid:1;", "syntax error");
    }

    @Test
    void legacy_modifier_without_a_content_is_a_syntax_error() {
        assertUnsupported("http.uri; http_header; content:\"a\"; sid:1;", "syntax error");
    }

    // ---- transforms ------------------------------------------------------------

    @Test
    void transforms_apply_in_rule_order_to_every_condition_on_the_sticky_buffer() {
        SuricataRule rule = active("http.uri; url_decode; to_lowercase; content:\"a\"; pcre:\"/b/\"; sid:1;");
        assertThat(content(rule, 0).transforms()).containsExactly(Transform.URL_DECODE, Transform.TO_LOWERCASE);
        assertThat(pcre(rule, 1).transforms()).containsExactly(Transform.URL_DECODE, Transform.TO_LOWERCASE);
    }

    @Test
    void a_new_sticky_buffer_clears_transforms() {
        SuricataRule rule = active("http.uri; compress_whitespace; content:\"a\"; http.header; content:\"b\"; sid:1;");
        assertThat(content(rule, 0).transforms()).containsExactly(Transform.COMPRESS_WHITESPACE);
        assertThat(content(rule, 1).transforms()).isEmpty();
    }

    @Test
    void a_transform_does_not_reach_back_to_an_earlier_content() {
        SuricataRule rule = active("http.uri; content:\"a\"; strip_whitespace; content:\"b\"; sid:1;");
        assertThat(content(rule, 0).transforms()).isEmpty();
        assertThat(content(rule, 1).transforms()).containsExactly(Transform.STRIP_WHITESPACE);
    }

    @Test
    void all_four_transforms_are_recognised() {
        SuricataRule rule = active("http.uri; url_decode; to_lowercase; compress_whitespace; strip_whitespace; content:\"a\"; sid:1;");
        assertThat(content(rule, 0).transforms()).containsExactly(Transform.values());
    }

    @Test
    void legacy_buffer_and_pcre_flag_content_take_no_sticky_transforms() {
        SuricataRule rule = active("http.uri; url_decode; content:\"a\"; http_header; pcre:\"/b/H\"; sid:1;");
        assertThat(content(rule, 0).transforms()).isEmpty();
        assertThat(pcre(rule, 1).transforms()).isEmpty();
    }

    @Test
    void transform_before_any_buffer_is_a_syntax_error() {
        assertUnsupported("url_decode; http.uri; content:\"a\"; sid:1;", "syntax error: 'url_decode' needs a buffer");
    }

    // ---- pcre ------------------------------------------------------------------

    @Test
    void pcre_uses_the_sticky_buffer_and_carries_its_flags() {
        SuricataRule rule = active("http.request_body; pcre:\"/a;b/ismR\"; sid:1;");
        PcreMatch match = pcre(rule, 0);
        assertThat(match.buffer()).isEqualTo(RuleBuffer.HTTP_REQUEST_BODY);
        assertThat(match.regex()).isEqualTo("a;b");
        assertThat(match.caseInsensitive()).isTrue();
        assertThat(match.dotAll()).isTrue();
        assertThat(match.multiline()).isTrue();
        assertThat(match.relative()).isTrue();
        assertThat(match.negated()).isFalse();
    }

    @Test
    void pcre_buffer_flag_overrides_the_sticky_buffer() {
        SuricataRule rule = active("http.header; pcre:\"/a/U\"; sid:1;");
        assertThat(pcre(rule, 0).buffer()).isEqualTo(RuleBuffer.HTTP_URI);
    }

    @Test
    void pcre_buffer_flag_alone_makes_the_pcre_inspectable() {
        SuricataRule rule = active("pcre:\"/a/C\"; sid:1;");
        assertThat(pcre(rule, 0).buffer()).isEqualTo(RuleBuffer.HTTP_COOKIE);
    }

    @Test
    void negated_pcre_is_marked() {
        assertThat(pcre(active("http.uri; pcre:!\"/a/\"; sid:1;"), 0).negated()).isTrue();
    }

    @Test
    void pcre_needing_backtracking_makes_the_rule_unsupported_with_the_linear_time_reason() {
        assertUnsupported("http.uri; pcre:\"/a(?=b)/\"; sid:1;", "pcre needs a feature a linear-time engine cannot provide");
        assertUnsupported("http.uri; pcre:\"/(a)\\1/\"; sid:1;", "linear-time engine");
        assertUnsupported("http.uri; pcre:\"/a++/\"; sid:1;", "linear-time engine");
        assertUnsupported("http.uri; pcre:\"/(?<!a)b/\"; sid:1;", "linear-time engine");
    }

    @Test
    void unsupported_pcre_flag_makes_the_rule_unsupported() {
        assertUnsupported("http.uri; pcre:\"/a/G\"; sid:1;", "pcre flag 'G'");
    }

    // ---- flow ------------------------------------------------------------------

    @Test
    void harmless_flow_settings_are_accepted() {
        for (String flow : List.of("to_server", "from_client", "established", "stateless", "only_stream", "no_stream",
                "established,to_server", "to_server, established")) {
            assertThat(http("flow:" + flow + "; http.uri; content:\"a\"; sid:1;").status()).as(flow).isEqualTo(RuleStatus.ACTIVE);
        }
    }

    @Test
    void response_flow_is_unsupported_with_the_response_reason() {
        for (String flow : List.of("to_client", "from_server", "established,to_client")) {
            assertUnsupported("flow:" + flow + "; http.uri; content:\"a\"; sid:1;",
                    "inspects responses, which Aegis does not inspect yet");
        }
    }

    @Test
    void unknown_flow_setting_is_unsupported() {
        assertUnsupported("flow:not_established; http.uri; content:\"a\"; sid:1;", "flow setting 'not_established'");
    }

    // ---- not applicable --------------------------------------------------------

    @Test
    void protocols_other_than_http_and_tcp_are_not_applicable() {
        for (String protocol : List.of("dns", "tls", "ssh", "smb", "ftp", "udp", "icmp", "ip", "smtp", "http2")) {
            ClassifiedRule result = classify("alert " + protocol + " any any -> any any (http.uri; content:\"a\"; sid:1;)");
            assertThat(result.status()).as(protocol).isEqualTo(RuleStatus.NOT_APPLICABLE);
            assertThat(result.reason()).contains(protocol);
            assertThat(result.sid()).isEqualTo(1);
        }
    }

    @Test
    void tcp_rules_with_http_buffers_are_active() {
        ClassifiedRule result = classify("alert tcp any any -> any 80 (http.uri; content:\"a\"; sid:1;)");
        assertThat(result.status()).isEqualTo(RuleStatus.ACTIVE);
    }

    @Test
    void content_before_any_buffer_targets_raw_payload() {
        ClassifiedRule result = http("content:\"abc\"; sid:1; rev:2;");
        assertThat(result.status()).isEqualTo(RuleStatus.NOT_APPLICABLE);
        assertThat(result.reason()).isEqualTo("matches raw TCP payload; Aegis inspects decoded HTTP");
        assertThat(result.sid()).isEqualTo(1);
        assertThat(result.rev()).isEqualTo(2);
    }

    @Test
    void pcre_before_any_buffer_targets_raw_payload() {
        assertThat(http("pcre:\"/abc/\"; sid:1;").status()).isEqualTo(RuleStatus.NOT_APPLICABLE);
    }

    @Test
    void one_raw_condition_makes_the_whole_rule_not_applicable() {
        assertThat(http("http.uri; content:\"a\"; sid:1;").status()).isEqualTo(RuleStatus.ACTIVE);
        assertThat(http("content:\"raw\"; http.uri; content:\"a\"; sid:1;").status()).isEqualTo(RuleStatus.NOT_APPLICABLE);
    }

    @Test
    void not_applicable_wins_over_unsupported_keywords() {
        ClassifiedRule dns = classify("alert dns any any -> any any (dns.query; content:\"a\"; flowbits:set,x; sid:1;)");
        assertThat(dns.status()).isEqualTo(RuleStatus.NOT_APPLICABLE);
        assertThat(http("flowbits:set,x; content:\"raw\"; sid:1;").status()).isEqualTo(RuleStatus.NOT_APPLICABLE);
    }

    @Test
    void content_after_an_unknown_buffer_keyword_is_not_mistaken_for_raw_payload() {
        assertUnsupported("http.stat_code; content:\"200\"; sid:1;", "http.stat_code");
        assertUnsupported("http.header_names; content:\"a\"; sid:1;", "http.header_names");
        assertUnsupported("some.future.buffer; content:\"a\"; sid:1;", "some.future.buffer");
    }

    // ---- unsupported -----------------------------------------------------------

    @Test
    void every_unsupported_keyword_is_named_in_the_reason() {
        for (String keyword : List.of("flowbits:set,x", "xbits:set,x,track ip_src", "threshold:type limit, track by_src, count 1, seconds 60",
                "detection_filter:track by_src, count 5, seconds 1", "byte_test:4,>,1,0", "byte_jump:2,0", "byte_extract:1,0,v",
                "isdataat:10", "dsize:>10", "urilen:>5", "bsize:>5", "lua:x.lua", "http.header_names", "http.accept",
                "http.referer", "tag:session,5,packets", "app-layer-protocol:http", "noalert", "rawbytes")) {
            String name = keyword.split("[:;]")[0];
            assertUnsupported(keyword + "; http.uri; content:\"a\"; sid:1;", "uses keyword '" + name + "', which Aegis does not support");
        }
    }

    @Test
    void response_side_buffers_are_unsupported_with_the_response_reason() {
        for (String buffer : List.of("http.stat_code", "http.stat_msg", "http.response_body", "http.response_line",
                "http.server", "http.location", "file.data", "file_data")) {
            assertUnsupported(buffer + "; content:\"a\"; sid:1;", buffer + "' inspects responses, which Aegis does not inspect yet");
        }
    }

    @Test
    void response_side_legacy_modifiers_are_unsupported_with_the_response_reason() {
        for (String modifier : List.of("http_stat_code", "http_stat_msg", "http_server_body")) {
            assertUnsupported("content:\"a\"; " + modifier + "; sid:1;", modifier + "' inspects responses");
        }
    }

    @Test
    void the_reason_names_the_first_offending_keyword() {
        assertUnsupported("flowbits:isset,a; byte_test:1,>,1,0; http.uri; content:\"a\"; sid:1;", "flowbits");
    }

    @Test
    void a_rule_with_no_content_or_pcre_is_unsupported() {
        assertUnsupported("flow:established,to_server; classtype:misc-activity; sid:1;", "no inspectable condition");
    }

    @Test
    void a_rule_with_only_a_sticky_buffer_and_no_condition_is_unsupported() {
        assertUnsupported("http.uri; sid:1;", "no inspectable condition");
    }

    @Test
    void out_of_range_or_malformed_explicit_score_is_unsupported() {
        assertUnsupported("http.uri; content:\"a\"; sid:1; metadata:score 101;", "score");
        assertUnsupported("http.uri; content:\"a\"; sid:1; metadata:score lots;", "score");
    }

    @Test
    void unknown_signature_severity_is_unsupported() {
        assertUnsupported("http.uri; content:\"a\"; sid:1; metadata:signature_severity Severe;", "signature_severity");
    }

    // ---- syntax errors -----------------------------------------------------------

    @Test
    void garbage_line_is_unsupported_with_sid_zero_and_a_syntax_error() {
        ClassifiedRule result = classify("this is not a rule at all");
        assertThat(result.status()).isEqualTo(RuleStatus.UNSUPPORTED);
        assertThat(result.sid()).isZero();
        assertThat(result.reason()).startsWith("syntax error: ");
    }

    @Test
    void rule_without_a_sid_is_unsupported_even_when_otherwise_fine() {
        ClassifiedRule result = http("http.uri; content:\"a\";");
        assertThat(result.status()).isEqualTo(RuleStatus.UNSUPPORTED);
        assertThat(result.reason()).isEqualTo("syntax error: rule has no sid");
    }

    @Test
    void rule_without_a_sid_is_unsupported_even_when_it_is_for_another_protocol() {
        ClassifiedRule result = classify("alert dns any any -> any any (content:\"a\";)");
        assertThat(result.status()).isEqualTo(RuleStatus.UNSUPPORTED);
    }

    @Test
    void malformed_sid_reports_that_problem() {
        assertUnsupported("http.uri; content:\"a\"; sid:abc;", "'sid' must be a positive whole number");
        assertUnsupported("http.uri; content:\"a\"; sid:0;", "'sid'");
    }

    @Test
    void malformed_rev_and_priority_are_syntax_errors() {
        assertUnsupported("http.uri; content:\"a\"; sid:1; rev:x;", "'rev'");
        assertUnsupported("http.uri; content:\"a\"; sid:1; priority:0;", "'priority'");
    }

    @Test
    void bad_hex_in_content_is_a_syntax_error_that_keeps_the_sid() {
        ClassifiedRule result = http("http.uri; content:\"|zz|\"; sid:9;");
        assertThat(result.status()).isEqualTo(RuleStatus.UNSUPPORTED);
        assertThat(result.reason()).startsWith("syntax error");
        assertThat(result.sid()).isEqualTo(9);
    }

    @Test
    void unterminated_quote_in_options_is_a_syntax_error_with_sid_zero() {
        ClassifiedRule result = http("msg:\"oops; http.uri; content:\"a\"; sid:9;");
        assertThat(result.status()).isEqualTo(RuleStatus.UNSUPPORTED);
        assertThat(result.reason()).startsWith("syntax error");
    }

    @Test
    void a_bad_line_does_not_stop_the_lines_after_it() {
        RuleSet set = parse("garbage\nalert http any any -> any any (http.uri; content:\"/a\"; sid:2;)\n");
        assertThat(set.rules()).extracting(ClassifiedRule::status).containsExactly(RuleStatus.UNSUPPORTED, RuleStatus.ACTIVE);
    }

    @Test
    void every_rule_line_yields_exactly_one_result_and_counts_add_up() {
        RuleSet set = parse("""
                alert http any any -> any any (http.uri; content:"/a"; sid:1;)
                alert dns any any -> any any (dns.query; content:"x"; sid:2;)
                alert http any any -> any any (flowbits:set,a; http.uri; content:"/a"; sid:3;)
                garbage
                """);
        assertThat(set.rules()).hasSize(4);
        assertThat(set.count(RuleStatus.ACTIVE)).isEqualTo(1);
        assertThat(set.count(RuleStatus.NOT_APPLICABLE)).isEqualTo(1);
        assertThat(set.count(RuleStatus.UNSUPPORTED)).isEqualTo(2);
        assertThat(set.activeRules()).extracting(SuricataRule::sid).containsExactly(1);
    }

    @Test
    void offset_values_are_stored_as_optional_ints() {
        ContentMatch match = content(active("http.uri; content:\"a\"; offset:0; sid:1;"), 0);
        assertThat(match.offset()).isEqualTo(OptionalInt.of(0));
    }
}
