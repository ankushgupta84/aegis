package io.aegis.tls;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.aegis.policy.UpstreamTls;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import io.netty.pkitesting.X509Bundle;
import io.netty.util.Mapping;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class UpstreamTlsContextsTest {

    private static final String BACKEND = "backend.example.com";

    @TempDir
    Path dir;

    @Test
    void plaintextUpstreamHasNoClientContext() {
        assertThatThrownBy(() -> UpstreamTlsContexts.clientContext(UpstreamTls.plaintext()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("not enabled");
    }

    @Test
    void aPinnedClientAcceptsTheSelfSignedOriginWhateverItsName() throws Exception {
        var origin = TestPki.ecServer("legacy.internal");

        var result = LoopbackHandshake.run(serving(origin), pinned(origin), BACKEND);

        assertThat(result.succeeded()).isTrue();
        assertThat(result.serverCertificate()).isEqualTo(origin.getCertificate());
    }

    @Test
    void aPinnedClientRejectsADifferentCertificateEvenWithTheSameName() throws Exception {
        var origin = TestPki.ecServer(BACKEND);
        var impostor = TestPki.ecServer(BACKEND);

        var result = LoopbackHandshake.run(serving(impostor), pinned(origin), BACKEND);

        assertThat(result.succeeded()).isFalse();
        assertThat(result.failure()).hasStackTraceContaining("pinned fingerprint");
    }

    @Test
    void aPinAcceptsUppercaseHex() throws Exception {
        var origin = TestPki.ecServer(BACKEND);
        var pin = UpstreamTlsContexts.sha256Fingerprint(origin.getCertificate()).toUpperCase();

        var client = UpstreamTlsContexts.clientContext(new UpstreamTls(true, Optional.empty(), Optional.of(pin)));

        assertThat(LoopbackHandshake.run(serving(origin), client, BACKEND).succeeded()).isTrue();
    }

    @Test
    void aMalformedPinIsRejectedWhenTheContextIsBuilt() {
        for (var pin : new String[] {"", "abc", "zz".repeat(32), "ab".repeat(33)}) {
            assertThatThrownBy(() -> UpstreamTlsContexts.clientContext(
                    new UpstreamTls(true, Optional.empty(), Optional.of(pin))))
                    .as("pin '%s'", pin)
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("64 hex digits");
        }
    }

    @Test
    void aCaClientAcceptsAChainFromThatCa() throws Exception {
        var ca = TestPki.ca("backend ca");
        var backend = TestPki.ecServerIssuedBy(ca, BACKEND);

        var result = LoopbackHandshake.run(serving(backend), trusting(ca), BACKEND);

        assertThat(result.succeeded()).isTrue();
    }

    @Test
    void aCaClientRejectsAChainFromAnotherCa() throws Exception {
        var ca = TestPki.ca("backend ca");
        var otherCa = TestPki.ca("other ca");
        var backend = TestPki.ecServerIssuedBy(otherCa, BACKEND);

        var result = LoopbackHandshake.run(serving(backend), trusting(ca), BACKEND);

        assertThat(result.succeeded()).isFalse();
    }

    @Test
    void aCaClientRejectsAHostnameMismatch() throws Exception {
        var ca = TestPki.ca("backend ca");
        var backend = TestPki.ecServerIssuedBy(ca, BACKEND);

        var result = LoopbackHandshake.run(serving(backend), trusting(ca), "other.example.com");

        assertThat(result.succeeded()).isFalse();
    }

    @Test
    void aCaClientRejectsASelfSignedCertificateThatIsNotInItsBundle() throws Exception {
        var ca = TestPki.ca("backend ca");
        var selfSigned = TestPki.ecServer(BACKEND);

        var result = LoopbackHandshake.run(serving(selfSigned), trusting(ca), BACKEND);

        assertThat(result.succeeded()).isFalse();
    }

    @Test
    void theDefaultTrustStoreRejectsAnUnknownCertificate() throws Exception {
        var unknown = TestPki.ecServer(BACKEND);
        var client = UpstreamTlsContexts.clientContext(new UpstreamTls(true, Optional.empty(), Optional.empty()));

        var result = LoopbackHandshake.run(serving(unknown), client, BACKEND);

        assertThat(result.succeeded()).isFalse();
    }

    @Test
    void anEmptyOrMissingCaFileIsRejectedWhenTheContextIsBuilt() throws Exception {
        var empty = Files.writeString(dir.resolve("empty.pem"), "");
        var missing = dir.resolve("missing.pem");

        for (var file : new Path[] {empty, missing}) {
            assertThatThrownBy(() -> UpstreamTlsContexts.clientContext(
                    new UpstreamTls(true, Optional.of(file), Optional.empty())))
                    .as(file.getFileName().toString())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining(file.toString());
        }
    }

    @Test
    void theFingerprintIsSha256OfTheDerEncodingAsLowercaseHex() throws Exception {
        var cert = TestPki.ecServer(BACKEND).getCertificate();
        var expected = new StringBuilder();
        for (byte b : MessageDigest.getInstance("SHA-256").digest(cert.getEncoded())) {
            expected.append(String.format("%02x", b));
        }

        var fingerprint = UpstreamTlsContexts.sha256Fingerprint(cert);

        assertThat(fingerprint).hasSize(64).isEqualTo(expected.toString()).isLowerCase();
    }

    private SslContext trusting(X509Bundle ca) throws Exception {
        var caFile = TestPki.writeCa(ca, dir.resolve("ca-" + System.nanoTime() + ".pem"));
        return UpstreamTlsContexts.clientContext(new UpstreamTls(true, Optional.of(caFile), Optional.empty()));
    }

    private static SslContext pinned(X509Bundle origin) {
        return UpstreamTlsContexts.clientContext(new UpstreamTls(true, Optional.empty(),
                Optional.of(UpstreamTlsContexts.sha256Fingerprint(origin.getCertificate()))));
    }

    private static Mapping<String, SslContext> serving(X509Bundle bundle) throws Exception {
        var context = SslContextBuilder.forServer(bundle.getKeyPair().getPrivate(), bundle.getCertificatePath())
                .sslProvider(SslProvider.JDK)
                .build();
        return name -> context;
    }
}
