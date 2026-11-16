package io.aegis.net;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.InetAddress;
import java.net.UnknownHostException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class CidrTest {

    private static InetAddress ip(String literal) {
        try {
            return InetAddress.getByName(literal);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Test
    void parsesAnIpv4Block() {
        Cidr cidr = Cidr.parse("10.0.0.0/8");

        assertThat(cidr.prefixBits()).isEqualTo(8);
        assertThat(cidr.contains(ip("10.255.0.1"))).isTrue();
    }

    @Test
    void parsesAnIpv6Block() {
        Cidr cidr = Cidr.parse("2001:db8::/32");

        assertThat(cidr.prefixBits()).isEqualTo(32);
        assertThat(cidr.contains(ip("2001:db8:ffff::1"))).isTrue();
    }

    @Test
    void treatsABareIpv4AddressAsASlash32() {
        Cidr cidr = Cidr.parse("192.0.2.7");

        assertThat(cidr.prefixBits()).isEqualTo(32);
        assertThat(cidr.contains(ip("192.0.2.7"))).isTrue();
        assertThat(cidr.contains(ip("192.0.2.8"))).isFalse();
    }

    @Test
    void treatsABareIpv6AddressAsASlash128() {
        Cidr cidr = Cidr.parse("2001:db8::1");

        assertThat(cidr.prefixBits()).isEqualTo(128);
        assertThat(cidr.contains(ip("2001:db8::2"))).isFalse();
    }

    @Test
    void stripsSurroundingWhitespace() {
        assertThat(Cidr.parse("  10.0.0.0/8 ")).isEqualTo(Cidr.parse("10.0.0.0/8"));
    }

    @Test
    void clearsHostBitsSoEquivalentBlocksAreEqual() {
        assertThat(Cidr.parse("10.1.2.3/8")).isEqualTo(Cidr.parse("10.0.0.0/8"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "   ", "/8", "10.0.0.0/", "10.0.0.0/33", "10.0.0.0/-1", "10.0.0.0/abc",
            "2001:db8::/129", "10.0.0.0/8/8", "256.0.0.1", "not an address", "10.0.0.0 /8"})
    void rejectsMalformedInput(String text) {
        assertThatThrownBy(() -> Cidr.parse(text))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("is not an IP address or CIDR block");
    }

    @ParameterizedTest
    // "bad.cafe" and "dead.beef" are made only of hex digits and dots, and "1.2.3.4.5" only of
    // digits and dots: each looks numeric yet would be resolved through DNS if it got that far.
    @ValueSource(strings = {"localhost", "example.com", "example.com/24", "my-host", "10.0.0.0.example.com",
            "bad.cafe", "dead.beef/16", "1.2.3.4.5", "1.2.3", "10.1"})
    void rejectsHostNames(String text) {
        assertThatThrownBy(() -> Cidr.parse(text)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void containsEveryAddressForSlash0() {
        Cidr everything = Cidr.parse("0.0.0.0/0");

        assertThat(everything.contains(ip("1.2.3.4"))).isTrue();
        assertThat(everything.contains(ip("255.255.255.255"))).isTrue();
    }

    @Test
    void matchesWholeBytesForSlash8() {
        Cidr cidr = Cidr.parse("10.0.0.0/8");

        assertThat(cidr.contains(ip("10.9.9.9"))).isTrue();
        assertThat(cidr.contains(ip("11.0.0.0"))).isFalse();
    }

    @Test
    void matchesPartialByteForSlash20() {
        Cidr cidr = Cidr.parse("192.168.16.0/20");

        assertThat(cidr.contains(ip("192.168.16.0"))).isTrue();
        assertThat(cidr.contains(ip("192.168.31.255"))).isTrue();
        assertThat(cidr.contains(ip("192.168.32.0"))).isFalse();
        assertThat(cidr.contains(ip("192.168.15.255"))).isFalse();
    }

    @Test
    void matchesExactlyOneAddressForSlash32() {
        Cidr cidr = Cidr.parse("192.0.2.1/32");

        assertThat(cidr.contains(ip("192.0.2.1"))).isTrue();
        assertThat(cidr.contains(ip("192.0.2.0"))).isFalse();
        assertThat(cidr.contains(ip("192.0.2.3"))).isFalse();
    }

    @Test
    void matchesWholeBytesForIpv6Slash64() {
        Cidr cidr = Cidr.parse("2001:db8:0:1::/64");

        assertThat(cidr.contains(ip("2001:db8:0:1:ffff:ffff:ffff:ffff"))).isTrue();
        assertThat(cidr.contains(ip("2001:db8:0:2::"))).isFalse();
    }

    @Test
    void matchesExactlyOneAddressForIpv6Slash128() {
        Cidr cidr = Cidr.parse("2001:db8::1/128");

        assertThat(cidr.contains(ip("2001:db8::1"))).isTrue();
        assertThat(cidr.contains(ip("2001:db8::3"))).isFalse();
    }

    @Test
    void matchesAcrossAPartialIpv6Byte() {
        Cidr cidr = Cidr.parse("2001:db8:8000::/33");

        assertThat(cidr.contains(ip("2001:db8:ffff::1"))).isTrue();
        assertThat(cidr.contains(ip("2001:db8:7fff::1"))).isFalse();
    }

    @Test
    void neverMatchesAcrossAddressFamilies() {
        assertThat(Cidr.parse("0.0.0.0/0").contains(ip("::1"))).isFalse();
        assertThat(Cidr.parse("::/0").contains(ip("1.2.3.4"))).isFalse();
    }

    @Test
    void buildsTheBlockContainingAnAddress() {
        Cidr block = Cidr.containing(ip("192.168.77.9"), 16);

        assertThat(block).isEqualTo(Cidr.parse("192.168.0.0/16"));
        assertThat(block.contains(ip("192.168.77.9"))).isTrue();
    }

    @Test
    void buildsTheIpv6BlockContainingAnAddress() {
        assertThat(Cidr.containing(ip("2001:db8:0:1:aaaa::5"), 64)).isEqualTo(Cidr.parse("2001:db8:0:1::/64"));
    }

    @Test
    void rejectsOutOfRangePrefixesWhenBuildingContainingBlocks() {
        assertThatThrownBy(() -> Cidr.containing(ip("1.2.3.4"), 33)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Cidr.containing(ip("1.2.3.4"), -1)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> Cidr.containing(ip("::1"), 129)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void comparesByNetworkAndPrefix() {
        assertThat(Cidr.parse("10.0.0.0/8"))
                .isEqualTo(Cidr.parse("10.0.0.0/8"))
                .hasSameHashCodeAs(Cidr.parse("10.9.9.9/8"))
                .isNotEqualTo(Cidr.parse("10.0.0.0/9"))
                .isNotEqualTo(Cidr.parse("11.0.0.0/8"))
                .isNotEqualTo("10.0.0.0/8");
    }

    @Test
    void printsInCanonicalForm() {
        assertThat(Cidr.parse("10.1.2.3/8")).hasToString("10.0.0.0/8");
        assertThat(Cidr.parse("192.0.2.7")).hasToString("192.0.2.7/32");
        assertThat(Cidr.parse("2001:db8::/32")).hasToString("2001:db8:0:0:0:0:0:0/32");
    }
}
