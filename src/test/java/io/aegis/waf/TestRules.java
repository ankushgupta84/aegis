package io.aegis.waf;

import io.aegis.http.RequestBuffers;
import io.aegis.http.RuleBuffer;
import io.aegis.rules.ClassifiedRule;
import io.aegis.rules.Condition;
import io.aegis.rules.ContentMatch;
import io.aegis.rules.PcreMatch;
import io.aegis.rules.RuleSet;
import io.aegis.rules.SuricataRule;
import io.aegis.rules.Transform;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.OptionalInt;

/** Builders that keep test rules to one readable line each. */
final class TestRules {

    private TestRules() {
    }

    static SuricataRule rule(int sid, Condition... conditions) {
        return scoredRule(sid, 5, conditions);
    }

    static SuricataRule scoredRule(int sid, int score, Condition... conditions) {
        return new SuricataRule(sid, 1, "alert", "rule " + sid, "web-application-attack", score,
                Map.of(), List.of(), List.of(conditions), "raw " + sid);
    }

    static RuleSet ruleSet(String name, SuricataRule... rules) {
        return new RuleSet(name, Arrays.stream(rules).map(ClassifiedRule::active).toList());
    }

    static RuleEngine engine(SuricataRule... rules) {
        return RuleEngine.compile(List.of(ruleSet("test", rules)));
    }

    /** A request whose buffers are the given ones, every other buffer empty. */
    static RequestBuffers request(RuleBuffer buffer, String content) {
        return requestOf(Map.of(buffer, content));
    }

    static RequestBuffers requestOf(Map<RuleBuffer, String> contents) {
        return buffer -> contents.getOrDefault(buffer, "");
    }

    static ContentBuilder content(RuleBuffer buffer, String pattern) {
        return new ContentBuilder(buffer, pattern);
    }

    static ContentBuilder uri(String pattern) {
        return content(RuleBuffer.HTTP_URI, pattern);
    }

    static PcreMatch pcre(RuleBuffer buffer, String regex, boolean negated, boolean relative) {
        return new PcreMatch(buffer, List.of(), regex, negated, false, false, false, relative);
    }

    /** Fluent construction of a {@link ContentMatch}, whose canonical constructor has twelve arguments. */
    static final class ContentBuilder {
        private final RuleBuffer buffer;
        private final String pattern;
        private List<Transform> transforms = List.of();
        private boolean negated;
        private boolean nocase;
        private OptionalInt offset = OptionalInt.empty();
        private OptionalInt depth = OptionalInt.empty();
        private OptionalInt distance = OptionalInt.empty();
        private OptionalInt within = OptionalInt.empty();
        private boolean startsWith;
        private boolean endsWith;
        private boolean fastPattern;

        private ContentBuilder(RuleBuffer buffer, String pattern) {
            this.buffer = buffer;
            this.pattern = pattern;
        }

        ContentBuilder transforms(Transform... transforms) {
            this.transforms = List.of(transforms);
            return this;
        }

        ContentBuilder negated() {
            negated = true;
            return this;
        }

        ContentBuilder nocase() {
            nocase = true;
            return this;
        }

        ContentBuilder offset(int offset) {
            this.offset = OptionalInt.of(offset);
            return this;
        }

        ContentBuilder depth(int depth) {
            this.depth = OptionalInt.of(depth);
            return this;
        }

        ContentBuilder distance(int distance) {
            this.distance = OptionalInt.of(distance);
            return this;
        }

        ContentBuilder within(int within) {
            this.within = OptionalInt.of(within);
            return this;
        }

        ContentBuilder startsWith() {
            startsWith = true;
            return this;
        }

        ContentBuilder endsWith() {
            endsWith = true;
            return this;
        }

        ContentBuilder fastPattern() {
            fastPattern = true;
            return this;
        }

        ContentMatch build() {
            return new ContentMatch(buffer, transforms, pattern, negated, nocase, offset, depth,
                    distance, within, startsWith, endsWith, fastPattern);
        }
    }
}
