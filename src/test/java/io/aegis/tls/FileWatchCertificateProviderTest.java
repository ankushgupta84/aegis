package io.aegis.tls;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.aegis.plugin.CertificateProvider.Material;
import io.aegis.plugin.CertificateUnavailableException;
import io.netty.pkitesting.CertificateBuilder;
import io.netty.pkitesting.X509Bundle;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class FileWatchCertificateProviderTest {

    @TempDir
    Path dir;

    private final List<Material> delivered = new ArrayList<>();
    private final List<CertificateUnavailableException> failures = new ArrayList<>();
    private FileWatchCertificateProvider provider;

    @AfterEach
    void closeProvider() {
        if (provider != null) {
            provider.close();
        }
    }

    @Test
    void loadsAnRsaChainAndKey() throws Exception {
        var bundle = TestPki.rsaServer("rsa.example.com");
        provider = providerFor(bundle);

        var material = provider.load();

        assertThat(material.chain()).containsExactly(bundle.getCertificatePath());
        assertThat(material.key()).isEqualTo(bundle.getKeyPair().getPrivate());
    }

    @Test
    void loadsAnEcChainAndKey() throws Exception {
        var bundle = TestPki.ecServer("ec.example.com");
        provider = providerFor(bundle);

        var material = provider.load();

        assertThat(material.chain().get(0)).isEqualTo(bundle.getCertificate());
        assertThat(material.key().getAlgorithm()).isEqualTo("EC");
    }

    @Test
    void loadsTheWholeChainLeafFirst() throws Exception {
        var ca = TestPki.ca("test ca");
        var leaf = TestPki.ecServerIssuedBy(ca, "chain.example.com");
        provider = providerFor(leaf);
        Files.writeString(dir.resolve("cert.pem"), leaf.getCertificatePEM() + ca.getCertificatePEM());

        var chain = provider.load().chain();

        assertThat(chain).containsExactly(leaf.getCertificate(), ca.getCertificate());
    }

    @Test
    void anExpiredCertificateStillLoadsAndShowsItsExpiry() throws Exception {
        var expired = new CertificateBuilder().ecp256().subject("CN=old.example.com").setIsCertificateAuthority(true)
                .notBefore(Instant.now().minus(Duration.ofDays(30)))
                .notAfter(Instant.now().minus(Duration.ofDays(1)))
                .buildSelfSigned();
        provider = providerFor(expired);

        var leaf = provider.load().chain().get(0);

        assertThat(leaf.getNotAfter().toInstant()).isBefore(Instant.now());
    }

    @Test
    void aKeyThatDoesNotMatchTheCertificateIsRejectedByName() throws Exception {
        var bundle = TestPki.ecServer("a.example.com");
        var other = TestPki.ecServer("b.example.com");
        provider = providerFor(bundle);
        Files.writeString(dir.resolve("key.pem"), other.getPrivateKeyPEM());

        assertThatThrownBy(provider::load)
                .isInstanceOf(CertificateUnavailableException.class)
                .hasMessageContaining("key.pem")
                .hasMessageContaining("does not match")
                .hasMessageContaining("cert.pem");
    }

    @Test
    void aRsaKeyForAnEcCertificateIsRejected() throws Exception {
        var ec = TestPki.ecServer("a.example.com");
        var rsa = TestPki.rsaServer("a.example.com");
        provider = providerFor(ec);
        Files.writeString(dir.resolve("key.pem"), rsa.getPrivateKeyPEM());

        assertThatThrownBy(provider::load)
                .isInstanceOf(CertificateUnavailableException.class)
                .hasMessageContaining("key.pem");
    }

    @Test
    void garbageInTheCertificateFileIsRejectedByName() throws Exception {
        provider = providerFor(TestPki.ecServer("a.example.com"));
        Files.writeString(dir.resolve("cert.pem"), "this is not a certificate");

        assertThatThrownBy(provider::load)
                .isInstanceOf(CertificateUnavailableException.class)
                .hasMessageContaining("cert.pem");
    }

    @Test
    void garbageInTheKeyFileIsRejectedByName() throws Exception {
        provider = providerFor(TestPki.ecServer("a.example.com"));
        Files.writeString(dir.resolve("key.pem"),
                "-----BEGIN PRIVATE KEY-----\nbm90IGEga2V5\n-----END PRIVATE KEY-----\n");

        assertThatThrownBy(provider::load)
                .isInstanceOf(CertificateUnavailableException.class)
                .hasMessageContaining("key.pem");
    }

    @Test
    void aKeyInAnotherPemFormatIsRejectedWithTheFix() throws Exception {
        provider = providerFor(TestPki.ecServer("a.example.com"));
        Files.writeString(dir.resolve("key.pem"),
                "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n");

        assertThatThrownBy(provider::load)
                .isInstanceOf(CertificateUnavailableException.class)
                .hasMessageContaining("PKCS#8");
    }

    @Test
    void aMissingFileIsRejectedByName() throws Exception {
        provider = providerFor(TestPki.ecServer("a.example.com"));
        Files.delete(dir.resolve("key.pem"));

        assertThatThrownBy(provider::load)
                .isInstanceOf(CertificateUnavailableException.class)
                .hasMessageContaining("key_file")
                .hasMessageContaining("key.pem");
    }

    @Test
    void aListenerThatThrowsIsReportedInsteadOfEndingTheWatch() throws Exception {
        provider = providerFor(TestPki.ecServer("a.example.com"));
        provider.load();
        provider.watch(material -> {
            throw new IllegalStateException("listener broke");
        }, failures::add);
        TestPki.write(TestPki.ecServer("a.example.com"), dir.resolve("cert.pem"), dir.resolve("key.pem"));

        provider.pollAndSurvive();

        assertThat(failures).singleElement()
                .satisfies(failure -> assertThat(failure).hasMessageContaining("listener broke"));
    }

    @Test
    void pollingDeliversNothingWhileTheFilesAreUnchanged() throws Exception {
        provider = providerFor(TestPki.ecServer("a.example.com"));
        provider.load();
        provider.watch(delivered::add, failures::add);

        provider.pollOnce();
        provider.pollOnce();

        assertThat(delivered).isEmpty();
        assertThat(failures).isEmpty();
    }

    @Test
    void aChangedCertificateIsDeliveredOnce() throws Exception {
        provider = providerFor(TestPki.ecServer("a.example.com"));
        provider.load();
        provider.watch(delivered::add, failures::add);
        var renewed = TestPki.ecServer("a.example.com");

        TestPki.write(renewed, dir.resolve("cert.pem"), dir.resolve("key.pem"));
        provider.pollOnce();
        provider.pollOnce();

        assertThat(delivered).hasSize(1);
        assertThat(delivered.get(0).chain().get(0)).isEqualTo(renewed.getCertificate());
        assertThat(failures).isEmpty();
    }

    @Test
    void aBrokenIntermediateStateIsReportedOnceAndRecoversWhenFixed() throws Exception {
        provider = providerFor(TestPki.ecServer("a.example.com"));
        provider.load();
        provider.watch(delivered::add, failures::add);
        var renewed = TestPki.ecServer("a.example.com");

        Files.writeString(dir.resolve("cert.pem"), renewed.getCertificatePathPEM());
        provider.pollOnce();
        provider.pollOnce();
        provider.pollOnce();

        assertThat(delivered).isEmpty();
        assertThat(failures).hasSize(1);
        assertThat(failures.get(0)).hasMessageContaining("does not match");

        Files.writeString(dir.resolve("key.pem"), renewed.getPrivateKeyPEM());
        provider.pollOnce();

        assertThat(delivered).hasSize(1);
        assertThat(delivered.get(0).chain().get(0)).isEqualTo(renewed.getCertificate());
        assertThat(failures).hasSize(1);
    }

    @Test
    void aFileThatDisappearsIsReportedOnceAndNothingIsDeliveredWhenItReturnsUnchanged() throws Exception {
        var bundle = TestPki.ecServer("a.example.com");
        provider = providerFor(bundle);
        provider.load();
        provider.watch(delivered::add, failures::add);

        Files.delete(dir.resolve("cert.pem"));
        provider.pollOnce();
        provider.pollOnce();
        Files.writeString(dir.resolve("cert.pem"), bundle.getCertificatePathPEM());
        provider.pollOnce();

        assertThat(failures).hasSize(1);
        assertThat(failures.get(0)).hasMessageContaining("cert_file");
        assertThat(delivered).isEmpty();
    }

    @Test
    void watchingTwiceIsAnError() throws Exception {
        provider = providerFor(TestPki.ecServer("a.example.com"));
        provider.watch(delivered::add, failures::add);

        assertThatThrownBy(() -> provider.watch(delivered::add, failures::add))
                .isInstanceOf(IllegalStateException.class);
    }

    private FileWatchCertificateProvider providerFor(X509Bundle bundle) throws IOException {
        var certFile = dir.resolve("cert.pem");
        var keyFile = dir.resolve("key.pem");
        TestPki.write(bundle, certFile, keyFile);
        return new FileWatchCertificateProvider(certFile, keyFile, Duration.ofHours(1));
    }
}
