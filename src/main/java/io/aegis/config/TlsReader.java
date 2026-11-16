package io.aegis.config;

import io.aegis.policy.TlsHost;
import io.aegis.policy.TlsMode;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Reads the {@code tls} list: which certificate Aegis presents for which hostname. */
final class TlsReader {
    private static final ValueType<TlsMode> MODE = ValueTypes.enumeration(TlsMode.class);

    private final Problems problems;
    private final Ledger ledger;

    TlsReader(Problems problems, Ledger ledger) {
        this.problems = problems;
        this.ledger = ledger;
    }

    List<TlsHost> read(Section root) {
        return root.children("tls", "hostname").stream()
                .map(this::host)
                .flatMap(Optional::stream)
                .toList();
    }

    private Optional<TlsHost> host(Section section) {
        int before = problems.count();
        Optional<String> hostname = section.required("hostname", ValueTypes.HOSTNAME);
        TlsMode mode = section.value("mode", MODE, TlsMode.REVERSE_PROXY);
        Section certificate = section.child("certificate");
        Optional<String> type = certificate.required("type", ValueTypes.TEXT);
        Map<String, String> settings = certificate.remainingText();
        // Setting values may be secrets, and the explanation is meant to be shared: list names only.
        ledger.record(certificate.label() + ".settings", settings.keySet().toString(), Ledger.SET_IN_FILE);
        if (problems.count() > before) {
            return Optional.empty();
        }
        return Optional.of(new TlsHost(hostname.get(), mode, type.get(), settings));
    }
}
