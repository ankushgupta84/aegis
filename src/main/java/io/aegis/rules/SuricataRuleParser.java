package io.aegis.rules;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Imports a Suricata 7 rule file as-is. Every rule line becomes exactly one {@link ClassifiedRule}
 * (active, not applicable, or unsupported with a reason) and the file never fails as a whole, so
 * an ET Open download can be dropped in unchanged. Rules Aegis cannot apply in full are skipped
 * whole: applying part of a rule would widen what it matches.
 *
 * <p>Bytes that are not valid UTF-8 become U+FFFD instead of failing the file; a rule that
 * carries one in a {@code content} is then rejected on its own as non-ASCII.
 */
public final class SuricataRuleParser {

    private SuricataRuleParser() {
    }

    public static RuleSet parse(String ruleSetName, Reader source) throws IOException {
        List<ClassifiedRule> rules = RuleLines.read(source).stream()
                .map(entry -> classify(entry.raw(), entry.text()))
                .toList();
        return new RuleSet(ruleSetName, rules);
    }

    public static RuleSet parseFile(String ruleSetName, Path file) throws IOException {
        try (Reader reader = new InputStreamReader(Files.newInputStream(file), StandardCharsets.UTF_8)) {
            return parse(ruleSetName, reader);
        }
    }

    private static ClassifiedRule classify(String raw, String text) {
        try {
            RuleHeader header = RuleHeader.parse(text);
            return RuleInterpreter.classify(header, OptionSplitter.split(header.optionText()), raw);
        } catch (Rejection rejection) {
            return ClassifiedRule.skipped(0, 0, RuleStatus.UNSUPPORTED, rejection.getMessage(), raw);
        }
    }
}
