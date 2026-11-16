package io.aegis.proxy;

import static org.assertj.core.api.Assertions.assertThat;

import io.aegis.config.ConfigLoader;
import io.aegis.rules.RuleStatus;
import io.aegis.rules.SuricataRuleParser;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ConfigCheckTest {

    @TempDir
    Path dir;

    @Test
    void reportsCountsPerRuleSetAndTheReasonsRulesWereSkipped() throws Exception {
        Path rules = Files.writeString(dir.resolve("mixed.rules"), """
                alert http any any -> any any (msg:"a"; http.uri; content:"x"; sid:1; rev:1;)
                alert http any any -> any any (msg:"b"; flowbits:set,seen; http.uri; content:"y"; sid:2; rev:1;)
                alert http any any -> any any (msg:"c"; flowbits:set,seen; http.uri; content:"z"; sid:3; rev:1;)
                """);
        String yaml = "profile: balanced\nlistener:\n  tls: false\nrule_sets:\n  - name: mixed\n    file: " + rules
                + "\n    mode: monitor\nroutes:\n  - name: web\n    backends: [127.0.0.1:9001]\n";
        var expected = SuricataRuleParser.parseFile("mixed", rules);

        String report = ConfigCheck.report(ConfigLoader.parse(yaml));

        assertThat(report).startsWith("rule set mixed: " + expected.count(RuleStatus.ACTIVE) + " active, "
                + expected.count(RuleStatus.NOT_APPLICABLE) + " not applicable, "
                + expected.count(RuleStatus.UNSUPPORTED) + " unsupported\n");
        assertThat(expected.count(RuleStatus.UNSUPPORTED)).isEqualTo(2);
        assertThat(report).containsPattern("\\n  2 x .*flowbits");
    }
}
