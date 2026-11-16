package io.aegis.http;

import io.aegis.policy.ClientIpPolicy;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

/**
 * Decides which address is the client's. A header can say anything, so it is believed only when
 * the connection comes from a proxy the operator trusts, and then only as far as the chain of
 * trusted proxies reaches.
 */
public final class ClientIpResolver {

    private final ClientIpPolicy policy;

    public ClientIpResolver(ClientIpPolicy policy) {
        this.policy = policy;
    }

    /**
     * @param peer the TCP peer address
     * @param xForwardedForValues every {@code X-Forwarded-For} header value, in the order sent
     * @return the peer if it is not a trusted proxy; otherwise the first hop from the right that
     *     is not a trusted proxy. An unparseable hop ends the walk and yields the hop to its
     *     right (or the peer if none), because nothing beyond it can be believed. If every hop
     *     is trusted, the leftmost hop.
     */
    public InetAddress resolve(InetAddress peer, List<String> xForwardedForValues) {
        if (!isTrusted(peer)) {
            return peer;
        }
        List<String> hops = splitHops(xForwardedForValues);
        InetAddress believed = peer;
        for (int i = hops.size() - 1; i >= 0; i--) {
            InetAddress hop = parseLiteral(hops.get(i));
            if (hop == null || !isTrusted(hop)) {
                return hop == null ? believed : hop;
            }
            believed = hop;
        }
        return believed;
    }

    private boolean isTrusted(InetAddress address) {
        return policy.trustedProxies().stream().anyMatch(block -> block.contains(address));
    }

    private static List<String> splitHops(List<String> headerValues) {
        List<String> hops = new ArrayList<>();
        for (String value : headerValues) {
            for (String hop : value.split(",", -1)) {
                hops.add(hop.strip());
            }
        }
        return hops;
    }

    /**
     * Parses an IP literal, or returns null. Only dotted-quad IPv4 and colon-form IPv6 are
     * accepted, which also guarantees {@link InetAddress#getByName} never queries DNS.
     */
    private static InetAddress parseLiteral(String hop) {
        boolean literal = isDottedQuad(hop) || isIpv6Shape(hop);
        if (!literal) {
            return null;
        }
        try {
            return InetAddress.getByName(hop);
        } catch (UnknownHostException e) {
            return null;
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
                && text.chars().allMatch(c -> isHexDigit(c) || c == ':' || c == '.');
    }

    private static boolean isHexDigit(int c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }
}
