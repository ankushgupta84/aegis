package io.aegis.firewall;

import static org.assertj.core.api.Assertions.assertThat;

import io.aegis.net.Cidr;
import io.aegis.policy.Exemption;
import io.aegis.policy.FirewallPolicy;
import io.aegis.policy.RateLimit;
import io.aegis.policy.Skip;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import org.junit.jupiter.api.Test;

class FirewallTest {

    private static final RateLimit OFF = new RateLimit(false, 1, 1, 32, 64, 10);
    private static final RateLimit ONE_REQUEST = new RateLimit(true, 1, 1, 32, 64, 10);

    private final FakeClock clock = new FakeClock();

    private static InetAddress ip(String literal) {
        try {
            return InetAddress.getByName(literal);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private static List<Cidr> cidrs(String... blocks) {
        return java.util.Arrays.stream(blocks).map(Cidr::parse).toList();
    }

    private static Exemption exemption(String source, Skip... skips) {
        return new Exemption("scanner", cidrs(source), List.of(skips), "internal scanner", "secops");
    }

    private Firewall firewall(List<Cidr> allow, List<Cidr> deny, RateLimit limit, Exemption... exemptions) {
        return new Firewall(new FirewallPolicy(allow, deny, limit, List.of(exemptions)), clock);
    }

    @Test
    void allowsEveryoneWhenNoListsAreConfiguredAndRateLimitIsOff() {
        Firewall firewall = firewall(List.of(), List.of(), OFF);

        assertThat(firewall.check(ip("192.0.2.1"))).isEqualTo(FirewallVerdict.ALLOW);
    }

    @Test
    void refusesClientsInTheDenyList() {
        Firewall firewall = firewall(List.of(), cidrs("192.0.2.0/24"), OFF);

        assertThat(firewall.check(ip("192.0.2.9"))).isEqualTo(FirewallVerdict.DENY_LISTED);
        assertThat(firewall.check(ip("198.51.100.1"))).isEqualTo(FirewallVerdict.ALLOW);
    }

    @Test
    void denyBeatsAllow() {
        Firewall firewall = firewall(cidrs("192.0.2.0/24"), cidrs("192.0.2.9"), OFF);

        assertThat(firewall.check(ip("192.0.2.9"))).isEqualTo(FirewallVerdict.DENY_LISTED);
        assertThat(firewall.check(ip("192.0.2.10"))).isEqualTo(FirewallVerdict.ALLOW);
    }

    @Test
    void admitsOnlyAllowListedClientsWhenAnAllowListExists() {
        Firewall firewall = firewall(cidrs("10.0.0.0/8", "2001:db8::/32"), List.of(), OFF);

        assertThat(firewall.check(ip("10.1.2.3"))).isEqualTo(FirewallVerdict.ALLOW);
        assertThat(firewall.check(ip("2001:db8::1"))).isEqualTo(FirewallVerdict.ALLOW);
        assertThat(firewall.check(ip("192.0.2.1"))).isEqualTo(FirewallVerdict.NOT_ALLOW_LISTED);
    }

    @Test
    void limitsTheRateOfAllowedClients() {
        Firewall firewall = firewall(List.of(), List.of(), ONE_REQUEST);

        assertThat(firewall.check(ip("192.0.2.1"))).isEqualTo(FirewallVerdict.ALLOW);
        assertThat(firewall.check(ip("192.0.2.1"))).isEqualTo(FirewallVerdict.RATE_LIMITED);
        clock.advanceNanos(1_000_000_000L);
        assertThat(firewall.check(ip("192.0.2.1"))).isEqualTo(FirewallVerdict.ALLOW);
    }

    @Test
    void doesNotChargeTokensForRefusedClients() {
        Firewall firewall = firewall(List.of(), cidrs("192.0.2.1"), ONE_REQUEST);

        firewall.check(ip("192.0.2.1"));

        assertThat(firewall.trackedClients()).isZero();
    }

    @Test
    void exemptionWithRateLimitSkipBypassesOnlyTheRateLimit() {
        Firewall firewall = firewall(List.of(), List.of(), ONE_REQUEST,
                exemption("192.0.2.1", Skip.rateLimit()));

        for (int i = 0; i < 5; i++) {
            assertThat(firewall.check(ip("192.0.2.1"))).isEqualTo(FirewallVerdict.ALLOW);
        }
        assertThat(firewall.check(ip("192.0.2.2"))).isEqualTo(FirewallVerdict.ALLOW);
        assertThat(firewall.check(ip("192.0.2.2"))).isEqualTo(FirewallVerdict.RATE_LIMITED);
    }

    @Test
    void exemptionNeverBypassesTheDenyList() {
        Firewall firewall = firewall(List.of(), cidrs("192.0.2.1"), ONE_REQUEST,
                exemption("192.0.2.1", Skip.rateLimit()));

        assertThat(firewall.check(ip("192.0.2.1"))).isEqualTo(FirewallVerdict.DENY_LISTED);
    }

    @Test
    void exemptionNeverBypassesTheAllowList() {
        Firewall firewall = firewall(cidrs("10.0.0.0/8"), List.of(), ONE_REQUEST,
                exemption("192.0.2.1", Skip.rateLimit()));

        assertThat(firewall.check(ip("192.0.2.1"))).isEqualTo(FirewallVerdict.NOT_ALLOW_LISTED);
    }

    @Test
    void ignoresExemptionSkipsOtherThanRateLimit() {
        Firewall firewall = firewall(List.of(), List.of(), ONE_REQUEST,
                exemption("192.0.2.1", Skip.waf(), Skip.ruleSet("et-open"), Skip.sid(2000001)));

        firewall.check(ip("192.0.2.1"));

        assertThat(firewall.check(ip("192.0.2.1"))).isEqualTo(FirewallVerdict.RATE_LIMITED);
    }

    @Test
    void honorsRateLimitSkipFromAnyApplicableExemption() {
        Firewall firewall = firewall(List.of(), List.of(), ONE_REQUEST,
                exemption("192.0.2.1", Skip.waf()),
                exemption("192.0.2.0/24", Skip.rateLimit()));

        firewall.check(ip("192.0.2.1"));

        assertThat(firewall.check(ip("192.0.2.1"))).isEqualTo(FirewallVerdict.ALLOW);
    }

    @Test
    void sharesOneBucketAcrossAnIpv6Slash64() {
        Firewall firewall = firewall(List.of(), List.of(), ONE_REQUEST);

        assertThat(firewall.check(ip("2001:db8:0:1::1"))).isEqualTo(FirewallVerdict.ALLOW);
        assertThat(firewall.check(ip("2001:db8:0:1::2"))).isEqualTo(FirewallVerdict.RATE_LIMITED);
    }

    @Test
    void givesEachIpv4AddressItsOwnBucket() {
        Firewall firewall = firewall(List.of(), List.of(), ONE_REQUEST);

        assertThat(firewall.check(ip("192.0.2.1"))).isEqualTo(FirewallVerdict.ALLOW);
        assertThat(firewall.check(ip("192.0.2.2"))).isEqualTo(FirewallVerdict.ALLOW);
    }

    @Test
    void boundsTrackedClientsAtTheConfiguredMaximum() {
        Firewall firewall = firewall(List.of(), List.of(), new RateLimit(true, 1, 1, 32, 64, 3));

        for (int i = 1; i <= 10; i++) {
            firewall.check(ip("192.0.2." + i));
        }

        assertThat(firewall.trackedClients()).isEqualTo(3);
    }

    @Test
    void refillNeverExceedsBurst() {
        Firewall firewall = firewall(List.of(), List.of(), new RateLimit(true, 1, 2, 32, 64, 10));
        firewall.check(ip("192.0.2.1"));
        firewall.check(ip("192.0.2.1"));

        clock.advanceNanos(100_000_000_000L);

        assertThat(firewall.check(ip("192.0.2.1"))).isEqualTo(FirewallVerdict.ALLOW);
        assertThat(firewall.check(ip("192.0.2.1"))).isEqualTo(FirewallVerdict.ALLOW);
        assertThat(firewall.check(ip("192.0.2.1"))).isEqualTo(FirewallVerdict.RATE_LIMITED);
    }
}
