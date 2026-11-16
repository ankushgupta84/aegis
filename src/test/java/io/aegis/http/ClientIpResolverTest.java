package io.aegis.http;

import static org.assertj.core.api.Assertions.assertThat;

import io.aegis.net.Cidr;
import io.aegis.policy.ClientIpPolicy;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import org.junit.jupiter.api.Test;

class ClientIpResolverTest {

    private final ClientIpResolver resolver = new ClientIpResolver(
            new ClientIpPolicy(List.of(Cidr.parse("10.0.0.0/8"), Cidr.parse("fd00::/8"))));

    private static InetAddress ip(String literal) {
        try {
            return InetAddress.getByName(literal);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private InetAddress resolve(String peer, String... xff) {
        return resolver.resolve(ip(peer), List.of(xff));
    }

    @Test
    void untrustedPeerIsTheClientAndSpoofedHeaderIsIgnored() {
        assertThat(resolve("203.0.113.9", "1.2.3.4")).isEqualTo(ip("203.0.113.9"));
    }

    @Test
    void trustedPeerWithoutHeaderIsItsOwnClient() {
        assertThat(resolve("10.0.0.1")).isEqualTo(ip("10.0.0.1"));
    }

    @Test
    void trustedPeerYieldsTheRightmostUntrustedHop() {
        assertThat(resolve("10.0.0.1", "198.51.100.7")).isEqualTo(ip("198.51.100.7"));
    }

    @Test
    void clientCannotPrependAFakeAddressToAChain() {
        assertThat(resolve("10.0.0.1", "6.6.6.6, 198.51.100.7, 10.0.0.2")).isEqualTo(ip("198.51.100.7"));
    }

    @Test
    void hopsAcrossSeveralHeadersAreWalkedAsOneChain() {
        assertThat(resolve("10.0.0.1", "6.6.6.6", "198.51.100.7, 10.0.0.2")).isEqualTo(ip("198.51.100.7"));
    }

    @Test
    void allHopsTrustedYieldsTheLeftmostHop() {
        assertThat(resolve("10.0.0.1", "10.1.1.1, 10.2.2.2")).isEqualTo(ip("10.1.1.1"));
    }

    @Test
    void ipv6HopsAreSupported() {
        assertThat(resolve("fd00::1", "2001:db8::5, fd00::2")).isEqualTo(ip("2001:db8::5"));
        assertThat(resolve("10.0.0.1", "2001:db8::5")).isEqualTo(ip("2001:db8::5"));
    }

    @Test
    void garbageHopStopsTheWalkAndYieldsTheHopToItsRight() {
        assertThat(resolve("10.0.0.1", "1.2.3.4, garbage, 10.0.0.2")).isEqualTo(ip("10.0.0.2"));
    }

    @Test
    void garbageRightmostHopYieldsThePeer() {
        assertThat(resolve("10.0.0.1", "1.2.3.4, garbage")).isEqualTo(ip("10.0.0.1"));
    }

    @Test
    void variousUnparseableHopsAreNeverTrusted() {
        for (String bad : List.of("", "unknown", "example.com", "1.2.3", "1.2.3.4.5", "256.1.1.1",
                "1.2.3.4:80", "1.2.3.4/24", "[::1]", "fe80::1%eth0", "1.2", "0x7f.0.0.1", "::g")) {
            assertThat(resolve("10.0.0.1", "6.6.6.6, " + bad + ", 10.0.0.2"))
                    .as("hop: '%s'", bad).isEqualTo(ip("10.0.0.2"));
        }
    }

    @Test
    void emptyElementInTheListIsGarbage() {
        assertThat(resolve("10.0.0.1", "6.6.6.6,,10.0.0.2")).isEqualTo(ip("10.0.0.2"));
    }

    @Test
    void emptyPolicyTrustsNoOne() {
        ClientIpResolver none = new ClientIpResolver(new ClientIpPolicy(List.of()));
        assertThat(none.resolve(ip("10.0.0.1"), List.of("1.2.3.4"))).isEqualTo(ip("10.0.0.1"));
    }
}
