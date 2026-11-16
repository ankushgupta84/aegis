package io.aegis.tls;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.aegis.plugin.CertificateProvider;
import io.aegis.plugin.CertificateProviderFactory;
import io.aegis.plugin.CertificateUnavailableException;
import io.aegis.policy.TlsHost;
import io.aegis.policy.TlsMode;
import io.aegis.policy.UpstreamTls;
import io.netty.buffer.ByteBufAllocator;
import io.netty.handler.ssl.ApplicationProtocolConfig;
import io.netty.handler.ssl.ApplicationProtocolConfig.Protocol;
import io.netty.handler.ssl.ApplicationProtocolConfig.SelectedListenerFailureBehavior;
import io.netty.handler.ssl.ApplicationProtocolConfig.SelectorFailureBehavior;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import io.netty.pkitesting.X509Bundle;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Real TLS handshakes against the contexts {@link ServerTls} hands to Netty's SniHandler. */
class ServerTlsHandshakeTest {

    @TempDir
    Path dir;

    private final List<CertificateEvent> events = new ArrayList<>();
    private final List<FileWatchCertificateProvider> providers = new ArrayList<>();
    private ServerTls serverTls;
    private X509Bundle ca;
    private SslContext client;

    @BeforeEach
    void trustTheTestCa() throws Exception {
        ca = TestPki.ca("test ca");
        client = UpstreamTlsContexts.clientContext(
                new UpstreamTls(true, Optional.of(TestPki.writeCa(ca, dir.resolve("ca.pem"))), Optional.empty()));
    }

    @AfterEach
    void closeServer() {
        if (serverTls != null) {
            serverTls.close();
        }
    }

    @Test
    void presentsTheCertificateOfTheRequestedName() throws Exception {
        var alpha = TestPki.ecServerIssuedBy(ca, "alpha.example.com");
        var beta = TestPki.ecServerIssuedBy(ca, "beta.example.com");
        open(host("alpha.example.com", alpha), host("beta.example.com", beta));

        assertThat(handshake("alpha.example.com").serverCertificate()).isEqualTo(alpha.getCertificate());
        assertThat(handshake("beta.example.com").serverCertificate()).isEqualTo(beta.getCertificate());
    }

    @Test
    void aWildcardMatchesExactlyOneLabel() throws Exception {
        var wildcard = TestPki.ecServerIssuedBy(ca, "*.example.com");
        open(host("*.example.com", wildcard));

        assertThat(handshake("a.example.com").succeeded()).isTrue();
        assertThat(handshake("a.b.example.com").succeeded()).isFalse();
        assertThat(handshake("example.com").succeeded()).isFalse();
        assertThatThrownBy(() -> serverTls.contextsBySni().map("a.b.example.com"))
                .isInstanceOf(SniContexts.UnknownServerNameException.class);
        assertThatThrownBy(() -> serverTls.contextsBySni().map("example.com"))
                .isInstanceOf(SniContexts.UnknownServerNameException.class);
    }

    @Test
    void anExactNameWinsOverAWildcard() throws Exception {
        var wildcard = TestPki.ecServerIssuedBy(ca, "*.example.com");
        var exact = TestPki.ecServerIssuedBy(ca, "www.example.com");
        open(host("*.example.com", wildcard), host("www.example.com", exact));

        assertThat(handshake("www.example.com").serverCertificate()).isEqualTo(exact.getCertificate());
        assertThat(handshake("api.example.com").serverCertificate()).isEqualTo(wildcard.getCertificate());
    }

    @Test
    void namesMatchRegardlessOfCase() throws Exception {
        open(host("Alpha.Example.com", TestPki.ecServerIssuedBy(ca, "alpha.example.com")));

        assertThat(serverTls.contextsBySni().map("ALPHA.example.COM")).isNotNull();
    }

    @Test
    void failsTheHandshakeForAnUnknownNameInsteadOfPresentingAnotherCertificate() throws Exception {
        var alpha = TestPki.ecServerIssuedBy(ca, "alpha.example.com");
        open(host("alpha.example.com", alpha));

        var result = LoopbackHandshake.run(serverTls.contextsBySni(), pinnedTo(alpha), "unknown.example.com");

        assertThat(result.succeeded()).isFalse();
        assertThat(result.serverCertificate()).isNull();
        assertThat(result.failure()).hasRootCauseInstanceOf(SniContexts.UnknownServerNameException.class);
    }

    @Test
    void failsTheHandshakeWhenTheClientSendsNoServerName() throws Exception {
        var alpha = TestPki.ecServerIssuedBy(ca, "alpha.example.com");
        open(host("alpha.example.com", alpha));

        var result = LoopbackHandshake.run(serverTls.contextsBySni(), pinnedTo(alpha), null);

        assertThat(result.succeeded()).isFalse();
        assertThat(result.serverCertificate()).isNull();
        assertThat(result.failure()).hasRootCauseInstanceOf(SniContexts.UnknownServerNameException.class);
    }

    @Test
    void aHandshakeAfterReloadSeesTheNewCertificate() throws Exception {
        var before = TestPki.ecServerIssuedBy(ca, "alpha.example.com");
        var after = TestPki.ecServerIssuedBy(ca, "alpha.example.com");
        var hostFiles = host("alpha.example.com", before);
        open(hostFiles);
        assertThat(handshake("alpha.example.com").serverCertificate()).isEqualTo(before.getCertificate());

        TestPki.write(after, dir.resolve("alpha.example.com.crt"), dir.resolve("alpha.example.com.key"));
        providers.get(0).pollOnce();

        assertThat(handshake("alpha.example.com").serverCertificate()).isEqualTo(after.getCertificate());
        assertThat(events).extracting(CertificateEvent::kind)
                .containsExactly(CertificateEvent.Kind.LOADED, CertificateEvent.Kind.RELOADED);
        assertThat(events.get(1).detail())
                .contains(UpstreamTlsContexts.sha256Fingerprint(after.getCertificate()));
    }

    @Test
    void aFailedReloadIsReportedAndTheOldCertificateKeepsServing() throws Exception {
        var before = TestPki.ecServerIssuedBy(ca, "alpha.example.com");
        open(host("alpha.example.com", before));

        Files.writeString(dir.resolve("alpha.example.com.crt"), "garbage");
        providers.get(0).pollOnce();

        assertThat(events).extracting(CertificateEvent::kind)
                .containsExactly(CertificateEvent.Kind.LOADED, CertificateEvent.Kind.RELOAD_FAILED);
        assertThat(events.get(1).hostname()).isEqualTo("alpha.example.com");
        assertThat(handshake("alpha.example.com").serverCertificate()).isEqualTo(before.getCertificate());
    }

    @Test
    void advertisesHttp11OnlyThroughAlpn() throws Exception {
        open(host("alpha.example.com", TestPki.ecServerIssuedBy(ca, "alpha.example.com")));

        assertThat(handshakeOffering("alpha.example.com", "h2", "http/1.1").alpn()).isEqualTo("http/1.1");
        assertThat(handshakeOffering("alpha.example.com", "h2").alpn()).isNull();
    }

    @Test
    void speaksTls12AndTls13OnlySoTls11IsRefused() throws Exception {
        open(host("alpha.example.com", TestPki.ecServerIssuedBy(ca, "alpha.example.com")));

        var enabled = serverTls.contextsBySni().map("alpha.example.com")
                .newEngine(ByteBufAllocator.DEFAULT).getEnabledProtocols();

        assertThat(enabled).containsExactlyInAnyOrder("TLSv1.2", "TLSv1.3");
        assertThat(handshake("alpha.example.com").protocol()).isEqualTo("TLSv1.3");
    }

    @Test
    void startupFailsWhenAnyHostCannotLoadAndNamesIt() throws Exception {
        var good = host("alpha.example.com", TestPki.ecServerIssuedBy(ca, "alpha.example.com"));
        var broken = new TlsHost("broken.example.com", TlsMode.REVERSE_PROXY, "file_watch",
                Map.of("cert_file", dir.resolve("absent.crt").toString(), "key_file", dir.resolve("absent.key").toString()));

        assertThatThrownBy(() -> open(good, broken))
                .isInstanceOf(CertificateUnavailableException.class)
                .hasMessageContaining("broken.example.com")
                .hasMessageContaining("absent.crt");
    }

    @Test
    void anUnknownProviderTypeNamesItAndTheAvailableTypes() {
        var host = new TlsHost("alpha.example.com", TlsMode.REVERSE_PROXY, "vault", Map.of());

        assertThatThrownBy(() -> ServerTls.open(List.of(host), events::add))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("'vault'")
                .hasMessageContaining("file_watch");
    }

    @Test
    void bundledProviderIsFoundWithoutInjectedFactories() throws Exception {
        var host = host("alpha.example.com", TestPki.ecServerIssuedBy(ca, "alpha.example.com"));

        serverTls = ServerTls.open(List.of(host), events::add);

        assertThat(handshake("alpha.example.com").succeeded()).isTrue();
    }

    @Test
    void theSameHostnameTwiceIsAnError() throws Exception {
        var bundle = TestPki.ecServerIssuedBy(ca, "alpha.example.com");

        assertThatThrownBy(() -> open(host("alpha.example.com", bundle), host("ALPHA.example.com", bundle)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("twice");
    }

    @Test
    void aWildcardAnywhereButTheFirstLabelIsAnError() {
        var host = new TlsHost("a.*.example.com", TlsMode.REVERSE_PROXY, "file_watch", Map.of());

        assertThatThrownBy(() -> open(host))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("a.*.example.com");
    }

    private void open(TlsHost... hosts) {
        var real = new FileWatchCertificateProviderFactory();
        CertificateProviderFactory recording = new CertificateProviderFactory() {
            @Override
            public String type() {
                return real.type();
            }

            @Override
            public CertificateProvider create(Map<String, String> settings) {
                var provider = (FileWatchCertificateProvider) real.create(settings);
                providers.add(provider);
                return provider;
            }
        };
        serverTls = ServerTls.open(List.of(hosts), Map.of(recording.type(), recording), events::add);
    }

    private TlsHost host(String hostname, X509Bundle bundle) throws IOException {
        var name = hostname.toLowerCase();
        var certFile = dir.resolve(name + ".crt");
        var keyFile = dir.resolve(name + ".key");
        TestPki.write(bundle, certFile, keyFile);
        return new TlsHost(hostname, TlsMode.REVERSE_PROXY, "file_watch", Map.of(
                "cert_file", certFile.toString(), "key_file", keyFile.toString(), "poll_interval", "1h"));
    }

    /**
     * A client that accepts the one certificate regardless of the name asked for, so a refusal can
     * only come from the server and not from the client's own hostname check.
     */
    private static SslContext pinnedTo(X509Bundle bundle) {
        return UpstreamTlsContexts.clientContext(new UpstreamTls(true, Optional.empty(),
                Optional.of(UpstreamTlsContexts.sha256Fingerprint(bundle.getCertificate()))));
    }

    private LoopbackHandshake handshake(String serverName) {
        return LoopbackHandshake.run(serverTls.contextsBySni(), client, serverName);
    }

    private LoopbackHandshake handshakeOffering(String serverName, String... protocols) throws Exception {
        var offering = SslContextBuilder.forClient()
                .sslProvider(SslProvider.JDK)
                .trustManager(ca.getRootCertificate())
                .applicationProtocolConfig(new ApplicationProtocolConfig(Protocol.ALPN,
                        SelectorFailureBehavior.NO_ADVERTISE, SelectedListenerFailureBehavior.ACCEPT, protocols))
                .build();
        return LoopbackHandshake.run(serverTls.contextsBySni(), offering, serverName);
    }
}
