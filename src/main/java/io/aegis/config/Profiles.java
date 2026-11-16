package io.aegis.config;

import io.aegis.policy.FailAction;
import io.aegis.policy.WafKnobs;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The built-in profiles: the complete WAF knob set each one starts from. This table is the one
 * place to audit what "strict", "balanced", and "easy" mean; it mirrors the table in the sample
 * configuration and in the design document.
 */
final class Profiles {
    private static final int BLOCK_THRESHOLD = 5;
    private static final int BODY_SCAN_LIMIT_BYTES = 128 * 1024;
    private static final Duration INSPECTION_BUDGET = Duration.ofMillis(5);

    private static final Map<String, WafKnobs> WAF_KNOBS = table();

    private Profiles() {
    }

    static List<String> names() {
        return List.copyOf(WAF_KNOBS.keySet());
    }

    static Optional<WafKnobs> wafKnobs(String profile) {
        return Optional.ofNullable(WAF_KNOBS.get(profile));
    }

    private static Map<String, WafKnobs> table() {
        Map<String, WafKnobs> table = new LinkedHashMap<>();
        //                                     body over limit    budget exceeded    engine error
        table.put("strict", knobs(FailAction.BLOCK, FailAction.BLOCK, FailAction.BLOCK));
        table.put("balanced", knobs(FailAction.PASS, FailAction.BLOCK, FailAction.BLOCK));
        table.put("easy", knobs(FailAction.PASS, FailAction.PASS, FailAction.PASS));
        return table;
    }

    private static WafKnobs knobs(FailAction onBodyOverLimit, FailAction onBudgetExceeded, FailAction onEngineError) {
        return new WafKnobs(BLOCK_THRESHOLD, BODY_SCAN_LIMIT_BYTES, onBodyOverLimit,
                INSPECTION_BUDGET, onBudgetExceeded, onEngineError);
    }
}
