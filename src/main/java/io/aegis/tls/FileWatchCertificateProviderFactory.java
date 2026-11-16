package io.aegis.tls;

import io.aegis.plugin.CertificateProvider;
import io.aegis.plugin.CertificateProviderFactory;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/** Creates {@link FileWatchCertificateProvider}s from the {@code file_watch} settings. */
public final class FileWatchCertificateProviderFactory implements CertificateProviderFactory {

    static final String TYPE = "file_watch";
    private static final Duration DEFAULT_POLL_INTERVAL = Duration.ofSeconds(5);
    private static final Set<String> KNOWN = Set.of("cert_file", "key_file", "poll_interval");

    @Override
    public String type() {
        return TYPE;
    }

    @Override
    public CertificateProvider create(Map<String, String> settings) {
        var unknown = new TreeSet<>(settings.keySet());
        unknown.removeAll(KNOWN);
        if (!unknown.isEmpty()) {
            throw new IllegalArgumentException("file_watch has no setting " + unknown
                    + "; the settings are cert_file, key_file and poll_interval");
        }
        var interval = settings.containsKey("poll_interval")
                ? parseInterval(settings.get("poll_interval"))
                : DEFAULT_POLL_INTERVAL;
        return new FileWatchCertificateProvider(
                Path.of(required(settings, "cert_file")), Path.of(required(settings, "key_file")), interval);
    }

    private static String required(Map<String, String> settings, String name) {
        var value = settings.get(name);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("file_watch needs the setting " + name);
        }
        return value;
    }

    /** Accepts a positive whole number with a unit: {@code ms}, {@code s}, {@code m} or {@code h}. */
    private static Duration parseInterval(String text) {
        var value = text.strip();
        try {
            if (value.endsWith("ms")) {
                return positive(Duration.ofMillis(Long.parseLong(value.substring(0, value.length() - 2))), text);
            }
            long amount = Long.parseLong(value.substring(0, value.length() - 1));
            return positive(switch (value.charAt(value.length() - 1)) {
                case 's' -> Duration.ofSeconds(amount);
                case 'm' -> Duration.ofMinutes(amount);
                case 'h' -> Duration.ofHours(amount);
                default -> throw new NumberFormatException();
            }, text);
        } catch (NumberFormatException | StringIndexOutOfBoundsException e) {
            throw invalidInterval(text);
        }
    }

    private static Duration positive(Duration duration, String text) {
        if (duration.isNegative() || duration.isZero()) {
            throw invalidInterval(text);
        }
        return duration;
    }

    private static IllegalArgumentException invalidInterval(String text) {
        return new IllegalArgumentException(
                "poll_interval '" + text + "' is not a positive duration such as 500ms, 5s, 1m or 1h");
    }
}
