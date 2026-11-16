package io.aegis.policy;

import io.aegis.net.Cidr;
import java.util.List;

/**
 * The IP access list and rate limit. This is a layer-7 access list, not a network firewall.
 *
 * @param allow      when non-empty, only these clients are admitted
 * @param deny       these clients are refused; deny wins over allow
 * @param exemptions only {@link Skip.Kind#RATE_LIMIT} skips are honored here
 */
public record FirewallPolicy(List<Cidr> allow, List<Cidr> deny, RateLimit rateLimit, List<Exemption> exemptions) {

    public FirewallPolicy {
        allow = List.copyOf(allow);
        deny = List.copyOf(deny);
        exemptions = List.copyOf(exemptions);
    }
}
