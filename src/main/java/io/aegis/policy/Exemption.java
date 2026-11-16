package io.aegis.policy;

import io.aegis.net.Cidr;
import java.net.InetAddress;
import java.util.List;

/**
 * A deliberate loosening of protection for named clients. Loosening must be visible, so an
 * exemption cannot exist without a reason and an owner.
 *
 * @param sources the clients this applies to
 * @param skips   exactly what those clients skip
 * @param reason  why the exemption exists
 * @param owner   who answers for it
 */
public record Exemption(String name, List<Cidr> sources, List<Skip> skips, String reason, String owner) {

    public Exemption {
        sources = List.copyOf(sources);
        skips = List.copyOf(skips);
        if (reason == null || reason.isBlank()) {
            throw new IllegalArgumentException("Exemption '" + name + "' needs a reason: say why it loosens protection");
        }
        if (owner == null || owner.isBlank()) {
            throw new IllegalArgumentException("Exemption '" + name + "' needs an owner: name who answers for it");
        }
    }

    public boolean appliesTo(InetAddress client) {
        return sources.stream().anyMatch(source -> source.contains(client));
    }
}
