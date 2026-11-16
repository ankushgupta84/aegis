package io.aegis.tls;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.aegis.plugin.CertificateProviderFactory;
import java.util.Map;
import java.util.ServiceLoader;
import org.junit.jupiter.api.Test;

class FileWatchCertificateProviderFactoryTest {

    private final FileWatchCertificateProviderFactory factory = new FileWatchCertificateProviderFactory();

    @Test
    void isDiscoveredThroughServiceLoaderAsFileWatch() {
        var types = ServiceLoader.load(CertificateProviderFactory.class).stream()
                .map(provider -> provider.get().type())
                .toList();

        assertThat(types).contains("file_watch");
    }

    @Test
    void createsAProviderFromCertAndKeyFiles() {
        try (var provider = factory.create(Map.of("cert_file", "c.pem", "key_file", "k.pem"))) {
            assertThat(provider).isInstanceOf(FileWatchCertificateProvider.class);
        }
    }

    @Test
    void acceptsEachDurationUnit() {
        for (var interval : new String[] {"250ms", "5s", "2m", "1h"}) {
            factory.create(Map.of("cert_file", "c.pem", "key_file", "k.pem", "poll_interval", interval)).close();
        }
    }

    @Test
    void aMissingCertFileIsExplainedInPlainLanguage() {
        assertThatThrownBy(() -> factory.create(Map.of("key_file", "k.pem")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("file_watch needs the setting cert_file");
    }

    @Test
    void aMissingKeyFileIsExplainedInPlainLanguage() {
        assertThatThrownBy(() -> factory.create(Map.of("cert_file", "c.pem")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("file_watch needs the setting key_file");
    }

    @Test
    void anUnknownSettingNamesItselfAndTheKnownOnes() {
        assertThatThrownBy(() -> factory.create(Map.of("cert_file", "c.pem", "key_file", "k.pem", "certfile", "x")))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("certfile")
                .hasMessageContaining("cert_file, key_file and poll_interval");
    }

    @Test
    void aBadPollIntervalIsRejected() {
        for (var interval : new String[] {"", "5", "fast", "0s", "-3s", "5d"}) {
            assertThatThrownBy(() -> factory.create(
                    Map.of("cert_file", "c.pem", "key_file", "k.pem", "poll_interval", interval)))
                    .as("interval '%s'", interval)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("poll_interval");
        }
    }
}
