package io.aegis.proxy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.JsonNode;
import io.aegis.loadtest.BackendOptions;
import io.aegis.loadtest.DummyBackend;
import io.aegis.tls.UpstreamTlsContexts;
import io.netty.pkitesting.X509Bundle;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.List;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** TLS on the listener, and TLS to the backends. */
class TlsEndToEndTest {

    @TempDir
    Path dir;

    private SSLSocket connect(int port, X509Bundle trustedCa, String serverName) throws Exception {
        KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType());
        trust.load(null, null);
        trust.setCertificateEntry("ca", trustedCa.getCertificate());
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init(trust);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, factory.getTrustManagers(), null);
        SSLSocket socket = (SSLSocket) context.getSocketFactory().createSocket("127.0.0.1", port);
        SSLParameters parameters = socket.getSSLParameters();
        parameters.setServerNames(List.of(new SNIHostName(serverName)));
        socket.setSSLParameters(parameters);
        return socket;
    }

    private String tlsEntry(X509Bundle server) throws Exception {
        Path cert = dir.resolve("server.crt");
        Path key = dir.resolve("server.key");
        TestPki.write(server, cert, key);
        return "tls:\n  - hostname: localhost\n    mode: reverse_proxy\n    certificate:\n      type: file_watch\n"
                + "      cert_file: " + cert + "\n      key_file: " + key + "\n";
    }

    @Test
    void theListenerServesTheConfiguredCertificateAndRefusesAnUnknownServerName() throws Exception {
        X509Bundle ca = TestPki.ca("test ca");
        X509Bundle server = TestPki.serverIssuedBy(ca, "localhost");
        try (ScriptedBackend backend = ScriptedBackend.answering("secure hello");
                TestProxy proxy = TestProxy.config(dir).backends(backend.port()).tls(tlsEntry(server)).start()) {
            try (SSLSocket socket = connect(proxy.port(), ca, "localhost");
                    RawClient client = new RawClient(socket, 5_000)) {
                socket.startHandshake();
                Certificate[] presented = socket.getSession().getPeerCertificates();
                RawClient.Response response = client.get("/");

                assertThat(presented[0]).isEqualTo(server.getCertificate());
                assertThat(response.text()).isEqualTo("secure hello");
                assertThat(backend.requests().get(0).header("X-Forwarded-Proto")).isEqualTo("https");
            }
            try (SSLSocket socket = connect(proxy.port(), ca, "unknown.example.com")) {
                assertThatThrownBy(socket::startHandshake).isInstanceOf(SSLException.class);
            }
            proxy.awaitEvent("certificate", e -> e.get("kind").asText().equals("loaded"));
            assertThat(proxy.admin("/metrics")).contains("aegis_certificate_events_total");
        }
    }

    private String upstreamTls(String trust) {
        return "upstream_tls:\n  enabled: true\n  " + trust + "\n";
    }

    private DummyBackend.Handle tlsBackend(X509Bundle backendCert) throws Exception {
        Path cert = dir.resolve("backend.crt");
        Path key = dir.resolve("backend.key");
        TestPki.write(backendCert, cert, key);
        return DummyBackend.start(BackendOptions.plain("tls-backend").withTls(new BackendOptions.TlsFiles(cert, key)));
    }

    @Test
    void upstreamTlsWithAPinnedFingerprintWorks() throws Exception {
        X509Bundle backendCert = TestPki.selfSignedServer("localhost");
        String pin = UpstreamTlsContexts.sha256Fingerprint(backendCert.getCertificate());
        try (DummyBackend.Handle backend = tlsBackend(backendCert);
                TestProxy proxy = TestProxy.config(dir).backends(backend.port())
                        .route(upstreamTls("pinned_sha256: \"" + pin + "\"")).start();
                RawClient client = new RawClient(proxy.port())) {
            RawClient.Response response = client.get("/");

            assertThat(response.status()).isEqualTo(200);
            assertThat(response.header("X-Backend")).isEqualTo("tls-backend");
        }
    }

    @Test
    void upstreamTlsWithAWrongPinYields502AndALoggedTlsFailure() throws Exception {
        X509Bundle backendCert = TestPki.selfSignedServer("localhost");
        String wrongPin = "0".repeat(64);
        try (DummyBackend.Handle backend = tlsBackend(backendCert);
                TestProxy proxy = TestProxy.config(dir).backends(backend.port())
                        .route(upstreamTls("pinned_sha256: \"" + wrongPin + "\"")).start();
                RawClient client = new RawClient(proxy.port())) {
            RawClient.Response response = client.get("/");

            assertThat(response.status()).isEqualTo(502);
            JsonNode failure = proxy.awaitEvent("backend_failure", e -> e.get("cause").asText().equals("tls_error"));
            assertThat(failure.get("request_id").asText()).isEqualTo(response.header("X-Request-Id"));
        }
    }
}
