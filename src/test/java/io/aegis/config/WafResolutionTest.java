package io.aegis.config;

import static org.assertj.core.api.Assertions.assertThat;

import io.aegis.policy.FailAction;
import io.aegis.policy.WafKnobs;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class WafResolutionTest {

    private static WafKnobs knobsOf(String yaml) {
        return ConfigLoader.parse(yaml).routes().get(0).waf().knobs();
    }

    private static String profile(String name) {
        return TestYaml.MINIMAL.replace("profile: balanced", "profile: " + name);
    }

    @ParameterizedTest(name = "{0} fails {1} on an oversize body, {2} over budget, {3} on engine error")
    @CsvSource({
        "strict,   BLOCK, BLOCK, BLOCK",
        "balanced, PASS,  BLOCK, BLOCK",
        "easy,     PASS,  PASS,  PASS"})
    void eachProfileHasItsOwnFailureActions(String profile, FailAction body, FailAction budget, FailAction engine) {
        WafKnobs knobs = knobsOf(profile(profile));
        assertThat(knobs.onBodyOverLimit()).isEqualTo(body);
        assertThat(knobs.onBudgetExceeded()).isEqualTo(budget);
        assertThat(knobs.onEngineError()).isEqualTo(engine);
    }

    @ParameterizedTest
    @CsvSource({"strict", "balanced", "easy"})
    void everyProfileSharesTheSameThresholdScanLimitAndBudget(String profile) {
        WafKnobs knobs = knobsOf(profile(profile));
        assertThat(knobs.blockThreshold()).isEqualTo(5);
        assertThat(knobs.bodyScanLimitBytes()).isEqualTo(128 * 1024);
        assertThat(knobs.inspectionBudget()).isEqualTo(Duration.ofMillis(5));
    }

    @Test
    void theGlobalWafSectionOverridesTheProfile() {
        WafKnobs knobs = knobsOf(TestYaml.plus("""
                waf:
                  block_threshold: 8
                  on_engine_error: pass
                """));
        assertThat(knobs.blockThreshold()).isEqualTo(8);
        assertThat(knobs.onEngineError()).isEqualTo(FailAction.PASS);
        assertThat(knobs.onBudgetExceeded()).isEqualTo(FailAction.BLOCK);
    }

    @Test
    void aRouteOverridesTheGlobalSectionAndLeavesOtherRoutesAlone() {
        var config = ConfigLoader.parse("""
                profile: strict
                listener:
                  tls: false
                waf:
                  body_scan_limit: 256KB
                  inspection_budget: 20ms
                routes:
                  - name: uploads
                    host: Uploads.Example.COM
                    backends: [127.0.0.1:9001]
                    waf:
                      body_scan_limit: 2MB
                  - name: api
                    backends: [127.0.0.1:9002]
                """);
        WafKnobs uploads = config.routes().get(0).waf().knobs();
        WafKnobs api = config.routes().get(1).waf().knobs();
        assertThat(uploads.bodyScanLimitBytes()).isEqualTo(2 * 1024 * 1024);
        assertThat(uploads.inspectionBudget()).isEqualTo(Duration.ofMillis(20));
        assertThat(api.bodyScanLimitBytes()).isEqualTo(256 * 1024);
        assertThat(api.inspectionBudget()).isEqualTo(Duration.ofMillis(20));
        assertThat(config.routes().get(0).host()).isEqualTo("uploads.example.com");
    }

    @Test
    void aRouteMayLoosenAKnobTheProfileSetStrict() {
        WafKnobs knobs = knobsOf(profile("strict").replace("backends: [127.0.0.1:9001]",
                "backends: [127.0.0.1:9001]\n    waf:\n      on_body_over_limit: pass"));
        assertThat(knobs.onBodyOverLimit()).isEqualTo(FailAction.PASS);
        assertThat(knobs.onEngineError()).isEqualTo(FailAction.BLOCK);
    }
}
