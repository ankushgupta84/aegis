package io.aegis.rules;

import java.util.Optional;

/** How serious a rule's match is, in the vocabulary of ET's {@code signature_severity} metadata. */
enum Severity {
    CRITICAL, MAJOR, MINOR, INFORMATIONAL;

    /** Suricata priority 1 is Major, 2 is Minor, and 3 and up are Informational. */
    static Severity fromPriority(int priority) {
        return priority == 1 ? MAJOR : priority == 2 ? MINOR : INFORMATIONAL;
    }

    static Optional<Severity> fromName(String name) {
        for (Severity severity : values()) {
            if (severity.name().equalsIgnoreCase(name)) {
                return Optional.of(severity);
            }
        }
        return Optional.empty();
    }
}
