package io.aegis.proxy;

import io.aegis.policy.RuleSetSource;
import io.aegis.rules.RuleSet;
import io.aegis.rules.SuricataRuleParser;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/** Reads and classifies every configured rule file. A file that cannot be read stops startup. */
final class RuleSetLoader {

    private RuleSetLoader() {
    }

    static List<RuleSet> load(List<RuleSetSource> sources) {
        List<RuleSet> sets = new ArrayList<>();
        for (RuleSetSource source : sources) {
            try {
                sets.add(SuricataRuleParser.parseFile(source.name(), source.file()));
            } catch (IOException e) {
                throw new StartupException("Cannot read rule file " + source.file() + " for rule set '"
                        + source.name() + "': " + e, e);
            }
        }
        return sets;
    }
}
