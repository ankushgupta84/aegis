package io.aegis.policy;

import io.aegis.net.Cidr;
import java.util.List;

/**
 * How Aegis decides who the client is. The TCP peer is the client unless the peer is one of
 * {@code trustedProxies}; then the client is the rightmost {@code X-Forwarded-For} hop that is
 * not itself a trusted proxy.
 */
public record ClientIpPolicy(List<Cidr> trustedProxies) {

    public ClientIpPolicy {
        trustedProxies = List.copyOf(trustedProxies);
    }
}
