package io.aegis.proxy;

import io.netty.pkitesting.CertificateBuilder;
import io.netty.pkitesting.X509Bundle;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** Certificates for the TLS tests, generated in memory and written as PEM files. */
final class TestPki {

    private TestPki() {
    }

    static X509Bundle ca(String name) throws Exception {
        return new CertificateBuilder().subject("CN=" + name).setIsCertificateAuthority(true).buildSelfSigned();
    }

    static X509Bundle serverIssuedBy(X509Bundle ca, String dnsName) throws Exception {
        return new CertificateBuilder().ecp256().subject("CN=" + dnsName).addSanDnsName(dnsName).buildIssuedBy(ca);
    }

    /** A self-signed server certificate, which is also a root, for pinning tests. */
    static X509Bundle selfSignedServer(String dnsName) throws Exception {
        return new CertificateBuilder().ecp256().subject("CN=" + dnsName).addSanDnsName(dnsName)
                .setIsCertificateAuthority(true).buildSelfSigned();
    }

    static void write(X509Bundle bundle, Path certFile, Path keyFile) throws IOException {
        Files.writeString(certFile, bundle.getCertificatePathPEM());
        Files.writeString(keyFile, bundle.getPrivateKeyPEM());
    }

    static Path writeCa(X509Bundle ca, Path file) throws IOException {
        return Files.writeString(file, ca.getRootCertificatePEM());
    }
}
