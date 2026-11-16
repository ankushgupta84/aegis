package io.aegis.config;

import io.aegis.policy.FailAction;
import io.aegis.policy.WafKnobs;
import java.util.Optional;

/**
 * Resolves each route's WAF knobs: the narrowest scope that sets a knob wins, from route to
 * global section to built-in profile. The winning scope is written to the ledger as the value is
 * chosen, so the explanation is a by-product of the resolution rather than a second computation.
 */
final class WafResolver {
    private static final ValueType<Integer> THRESHOLD = ValueTypes.integer(1, Integer.MAX_VALUE);
    private static final ValueType<FailAction> FAIL_ACTION = ValueTypes.enumeration(FailAction.class);

    private final String profileName;
    private final WafKnobs profile;
    private final WafOverrides global;
    private final Ledger ledger;

    WafResolver(String profileName, WafKnobs profile, WafOverrides global, Ledger ledger) {
        this.profileName = profileName;
        this.profile = profile;
        this.global = global;
        this.ledger = ledger;
    }

    /** The knobs for the route called {@code routeName}, whose knob paths start with {@code routeLabel}. */
    WafKnobs resolve(String routeLabel, String routeName, WafOverrides route) {
        String path = routeLabel + ".waf.";
        String scope = "route " + routeName;
        return new WafKnobs(
                pick(path + "block_threshold", THRESHOLD, scope,
                        route.blockThreshold(), global.blockThreshold(), profile.blockThreshold()),
                pick(path + "body_scan_limit", ValueTypes.BYTES_AS_INT, scope,
                        route.bodyScanLimitBytes(), global.bodyScanLimitBytes(), profile.bodyScanLimitBytes()),
                pick(path + "on_body_over_limit", FAIL_ACTION, scope,
                        route.onBodyOverLimit(), global.onBodyOverLimit(), profile.onBodyOverLimit()),
                pick(path + "inspection_budget", ValueTypes.DURATION, scope,
                        route.inspectionBudget(), global.inspectionBudget(), profile.inspectionBudget()),
                pick(path + "on_budget_exceeded", FAIL_ACTION, scope,
                        route.onBudgetExceeded(), global.onBudgetExceeded(), profile.onBudgetExceeded()),
                pick(path + "on_engine_error", FAIL_ACTION, scope,
                        route.onEngineError(), global.onEngineError(), profile.onEngineError()));
    }

    private <T> T pick(String path, ValueType<T> type, String routeScope,
                       Optional<T> route, Optional<T> global, T profileValue) {
        if (route.isPresent()) {
            return recorded(path, type, route.get(), routeScope);
        }
        if (global.isPresent()) {
            return recorded(path, type, global.get(), "global waf");
        }
        return recorded(path, type, profileValue, "profile " + profileName);
    }

    private <T> T recorded(String path, ValueType<T> type, T value, String source) {
        ledger.record(path, type.show(value), source);
        return value;
    }
}
