package io.aegis.policy;

import java.util.List;

/**
 * The whole configuration, validated and resolved. Nothing downstream reads YAML or applies a
 * default: if a value is here, it is the value in force.
 *
 * @param profile the built-in profile the configuration starts from: strict, balanced, or easy
 * @param routes  in match order; the first route whose host and path prefix fit a request serves it
 */
public record AegisConfig(
        String profile,
        Listener listener,
        Admin admin,
        LogSettings log,
        ClientIpPolicy clientIp,
        FirewallPolicy firewall,
        List<RuleSetSource> ruleSets,
        List<TlsHost> tlsHosts,
        List<RoutePolicy> routes) {

    public AegisConfig {
        ruleSets = List.copyOf(ruleSets);
        tlsHosts = List.copyOf(tlsHosts);
        routes = List.copyOf(routes);
    }
}
