package io.aegis.firewall;

import io.aegis.net.Cidr;
import io.aegis.policy.Exemption;
import io.aegis.policy.FirewallPolicy;
import io.aegis.policy.Skip;
import java.net.InetAddress;
import java.util.List;
import java.util.function.LongSupplier;

/**
 * The layer-7 IP access list and rate limit. Safe to call from many threads.
 *
 * <p>Order matters: deny beats allow, and exemptions can lift only the rate limit. An exemption
 * that could bypass the deny list would give a compromised internal host a free pass.
 */
public final class Firewall {

    private final List<Cidr> allow;
    private final List<Cidr> deny;
    private final List<Exemption> exemptions;
    private final TokenBucketLimiter limiter;

    public Firewall(FirewallPolicy policy, LongSupplier nanoClock) {
        this.allow = policy.allow();
        this.deny = policy.deny();
        this.exemptions = policy.exemptions();
        this.limiter = policy.rateLimit().enabled() ? new TokenBucketLimiter(policy.rateLimit(), nanoClock) : null;
    }

    /** Decides whether {@code client} may proceed; charges one rate-limit token when it applies. */
    public FirewallVerdict check(InetAddress client) {
        if (isInAny(deny, client)) {
            return FirewallVerdict.DENY_LISTED;
        }
        if (!allow.isEmpty() && !isInAny(allow, client)) {
            return FirewallVerdict.NOT_ALLOW_LISTED;
        }
        if (limiter != null && !isExemptFromRateLimit(client) && !limiter.tryAcquire(client)) {
            return FirewallVerdict.RATE_LIMITED;
        }
        return FirewallVerdict.ALLOW;
    }

    /** How many clients currently hold a rate-limit bucket; zero when rate limiting is off. */
    public int trackedClients() {
        return limiter == null ? 0 : limiter.trackedClients();
    }

    private static boolean isInAny(List<Cidr> blocks, InetAddress client) {
        return blocks.stream().anyMatch(block -> block.contains(client));
    }

    private boolean isExemptFromRateLimit(InetAddress client) {
        return exemptions.stream()
                .filter(exemption -> exemption.appliesTo(client))
                .anyMatch(exemption -> exemption.skips().stream()
                        .anyMatch(skip -> skip.kind() == Skip.Kind.RATE_LIMIT));
    }
}
