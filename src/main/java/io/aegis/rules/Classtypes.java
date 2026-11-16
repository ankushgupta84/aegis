package io.aegis.rules;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Suricata's stock {@code classification.config}: every classtype with its default priority,
 * grouped here by the {@link Category} Aegis scores it under. Classtypes not listed score as
 * {@link Category#MISC} at priority 3, which is what Suricata assumes for them.
 */
final class Classtypes {

    /** What the table knows about one classtype. */
    record Entry(Category category, int priority) {
    }

    static final int UNKNOWN_PRIORITY = 3;

    private static final Map<String, Entry> TABLE = new HashMap<>();

    static {
        // Category, default priority, classtypes.
        add(Category.ATTACK, 1, "attempted-admin", "attempted-user", "successful-admin", "successful-user",
                "unsuccessful-user", "web-application-attack", "trojan-activity", "shellcode-detect",
                "exploit-kit", "command-and-control", "domain-c2", "client-side-exploit", "credential-theft",
                "targeted-activity");
        add(Category.ATTACK, 2, "attempted-dos", "denial-of-service", "successful-dos", "misc-attack",
                "default-login-attempt", "suspicious-login", "system-call-detect", "social-engineering");
        add(Category.RECON, 2, "attempted-recon", "successful-recon-limited", "successful-recon-largescale",
                "rpc-portmap-decode");
        add(Category.RECON, 3, "network-scan");
        add(Category.POLICY, 1, "policy-violation", "inappropriate-content");
        add(Category.POLICY, 2, "pup-activity", "coin-mining", "external-ip-check");
        add(Category.MISC, 2, "bad-unknown", "non-standard-protocol", "suspicious-filename-detect",
                "unusual-client-port-connection", "web-application-activity");
        add(Category.MISC, 3, "unknown", "misc-activity", "icmp-event", "not-suspicious",
                "protocol-command-decode", "string-detect");
        add(Category.MISC, 4, "tcp-connection");
    }

    private Classtypes() {
    }

    private static void add(Category category, int priority, String... names) {
        for (String name : names) {
            TABLE.put(name, new Entry(category, priority));
        }
    }

    static Optional<Entry> find(String classtype) {
        return Optional.ofNullable(TABLE.get(classtype));
    }
}
