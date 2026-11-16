package io.aegis.corerules;

import io.aegis.http.ParsedRequest;
import io.aegis.policy.FailAction;
import io.aegis.policy.RuleMode;
import io.aegis.policy.WafKnobs;
import io.aegis.policy.WafPolicy;
import io.aegis.rules.RuleSet;
import io.aegis.rules.SuricataRuleParser;
import io.aegis.waf.RuleEngine;
import io.aegis.waf.RuleHit;
import io.aegis.waf.Waf;
import io.aegis.waf.WafVerdict;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/** The shipped core ruleset, compiled and wired into a {@link Waf} in block mode exactly as a route would run it. */
final class CoreRules {

    static final String RULE_SET_NAME = "aegis-core";
    static final int THRESHOLD = 5;
    private static final Path FILE = Path.of("config/rules/aegis-core.rules");
    private static final CoreRules SHARED = load();

    private final RuleSet ruleSet;
    private final RuleEngine engine;
    private final Waf waf;

    /** What the WAF decided for one request. */
    record Outcome(CorpusRequest request, WafVerdict verdict) {

        boolean blocked() {
            return verdict.blocked();
        }

        int score() {
            return verdict.score();
        }

        List<Integer> sids() {
            return verdict.hits().stream().map(RuleHit::sid).toList();
        }

        @Override
        public String toString() {
            return request.id() + " score=" + score() + " sids=" + sids();
        }
    }

    private CoreRules(RuleSet ruleSet, RuleEngine engine, Waf waf) {
        this.ruleSet = ruleSet;
        this.engine = engine;
        this.waf = waf;
    }

    static CoreRules shared() {
        return SHARED;
    }

    private static CoreRules load() {
        try {
            RuleSet ruleSet = SuricataRuleParser.parseFile(RULE_SET_NAME, FILE);
            RuleEngine engine = RuleEngine.compile(List.of(ruleSet));
            WafKnobs knobs = new WafKnobs(THRESHOLD, 1 << 20, FailAction.BLOCK, Duration.ofSeconds(30),
                    FailAction.BLOCK, FailAction.BLOCK);
            WafPolicy policy = new WafPolicy(knobs, Map.of(RULE_SET_NAME, RuleMode.BLOCK), Map.of(), Map.of(), List.of());
            Waf waf = new Waf(engine, policy, System::nanoTime, error -> {
                throw error;
            });
            return new CoreRules(ruleSet, engine, waf);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    RuleSet ruleSet() {
        return ruleSet;
    }

    RuleEngine engine() {
        return engine;
    }

    Outcome evaluate(CorpusRequest request) {
        ParsedRequest parsed = request.toParsedRequest();
        return new Outcome(request, waf.evaluate(parsed, client(), parsed.bodyTruncated()));
    }

    private static InetAddress client() {
        try {
            return InetAddress.getByName("203.0.113.9");
        } catch (UnknownHostException e) {
            throw new IllegalStateException(e);
        }
    }
}
