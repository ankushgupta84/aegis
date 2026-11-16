package io.aegis.net;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;

/**
 * An IPv4 or IPv6 address block, such as {@code 10.0.0.0/8} or {@code 2001:db8::/32}.
 *
 * <p>A bare address is a block of one: {@code 192.0.2.7} means {@code 192.0.2.7/32}.
 * An IPv4 block never contains an IPv6 address, and the reverse.
 */
public final class Cidr {

    private final byte[] network;
    private final int prefixBits;

    private Cidr(byte[] network, int prefixBits) {
        this.network = network;
        this.prefixBits = prefixBits;
    }

    /**
     * Parses {@code address} or {@code address/prefix}. Host names are rejected: a block that
     * depends on a DNS answer could change under the operator's feet.
     *
     * @throws IllegalArgumentException with a message that names the bad input and what is valid
     */
    public static Cidr parse(String text) {
        String trimmed = text.strip();
        int slash = trimmed.indexOf('/');
        String addressPart = slash < 0 ? trimmed : trimmed.substring(0, slash);

        byte[] address = literalAddress(addressPart, text);
        int maxBits = address.length * 8;
        int prefix = slash < 0 ? maxBits : prefixLength(trimmed.substring(slash + 1), maxBits, text);
        return new Cidr(masked(address, prefix), prefix);
    }

    /** The block of {@code prefixBits} that contains {@code address}. */
    public static Cidr containing(InetAddress address, int prefixBits) {
        byte[] bytes = address.getAddress();
        if (prefixBits < 0 || prefixBits > bytes.length * 8) {
            throw new IllegalArgumentException(
                    "Prefix /" + prefixBits + " is out of range for " + address.getHostAddress());
        }
        return new Cidr(masked(bytes, prefixBits), prefixBits);
    }

    public boolean contains(InetAddress address) {
        byte[] candidate = address.getAddress();
        if (candidate.length != network.length) {
            return false;
        }
        int wholeBytes = prefixBits / 8;
        for (int i = 0; i < wholeBytes; i++) {
            if (candidate[i] != network[i]) {
                return false;
            }
        }
        int remainingBits = prefixBits % 8;
        if (remainingBits == 0) {
            return true;
        }
        int mask = 0xFF << (8 - remainingBits);
        return (candidate[wholeBytes] & mask) == (network[wholeBytes] & mask);
    }

    public int prefixBits() {
        return prefixBits;
    }

    private static byte[] literalAddress(String addressPart, String original) {
        // Only shapes that InetAddress treats as literals may reach it: anything else would be
        // looked up in DNS, and a block must never depend on a DNS answer.
        if (!isDottedQuad(addressPart) && !isIpv6Shape(addressPart)) {
            throw invalid(original);
        }
        try {
            return InetAddress.getByName(addressPart).getAddress();
        } catch (UnknownHostException e) {
            throw invalid(original);
        }
    }

    private static boolean isDottedQuad(String text) {
        String[] parts = text.split("\\.", -1);
        if (parts.length != 4) {
            return false;
        }
        for (String part : parts) {
            boolean number = !part.isEmpty() && part.length() <= 3
                    && part.chars().allMatch(c -> c >= '0' && c <= '9');
            if (!number || Integer.parseInt(part) > 255) {
                return false;
            }
        }
        return true;
    }

    private static boolean isIpv6Shape(String text) {
        return text.indexOf(':') >= 0
                && text.chars().allMatch(c -> Character.digit(c, 16) >= 0 || c == ':' || c == '.');
    }

    private static int prefixLength(String prefixPart, int maxBits, String original) {
        try {
            int prefix = Integer.parseInt(prefixPart);
            if (prefix >= 0 && prefix <= maxBits) {
                return prefix;
            }
        } catch (NumberFormatException e) {
            // Falls through to the shared error below.
        }
        throw invalid(original);
    }

    private static byte[] masked(byte[] address, int prefixBits) {
        byte[] result = address.clone();
        for (int bit = prefixBits; bit < result.length * 8; bit++) {
            result[bit / 8] &= (byte) ~(0x80 >> (bit % 8));
        }
        return result;
    }

    private static IllegalArgumentException invalid(String text) {
        return new IllegalArgumentException("'" + text + "' is not an IP address or CIDR block. "
                + "Valid examples: 192.0.2.7, 10.0.0.0/8, 2001:db8::/32.");
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof Cidr that
                && prefixBits == that.prefixBits
                && Arrays.equals(network, that.network);
    }

    @Override
    public int hashCode() {
        return 31 * Arrays.hashCode(network) + prefixBits;
    }

    @Override
    public String toString() {
        try {
            return InetAddress.getByAddress(network).getHostAddress() + "/" + prefixBits;
        } catch (UnknownHostException e) {
            throw new IllegalStateException("A Cidr always holds 4 or 16 bytes", e);
        }
    }
}
