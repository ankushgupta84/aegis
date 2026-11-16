package io.aegis.tls;

import io.netty.pkitesting.CertificateBuilder;
import io.netty.pkitesting.X509Bundle;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/** Certificates for tests, generated in memory and written as PEM files where a test needs files. */
final class TestPki {

    private TestPki() {
    }

    static X509Bundle ca(String name) throws Exception {
        return new CertificateBuilder().subject("CN=" + name).setIsCertificateAuthority(true).buildSelfSigned();
    }

    static X509Bundle rsaServer(String dnsName) throws Exception {
        return selfSigned(new CertificateBuilder().rsa2048(), dnsName);
    }

    static X509Bundle ecServer(String dnsName) throws Exception {
        return selfSigned(new CertificateBuilder().ecp256(), dnsName);
    }

    static X509Bundle ecServerIssuedBy(X509Bundle ca, String dnsName) throws Exception {
        if (dnsName.startsWith("*")) {
            return wildcardServer(dnsName).buildIssuedBy(ca);
        }
        return server(new CertificateBuilder().ecp256(), dnsName).buildIssuedBy(ca);
    }

    /**
     * The library's {@code addSanDnsName} rejects '*', so the subjectAltName extension is encoded
     * by hand: SEQUENCE { [2] IA5String name }, short-form lengths.
     */
    private static CertificateBuilder wildcardServer(String pattern) {
        var name = pattern.getBytes(StandardCharsets.US_ASCII);
        var san = new byte[name.length + 4];
        san[0] = 0x30;
        san[1] = (byte) (name.length + 2);
        san[2] = (byte) 0x82;
        san[3] = (byte) name.length;
        System.arraycopy(name, 0, san, 4, name.length);
        return new CertificateBuilder().ecp256().subject("CN=" + pattern)
                .addExtensionOctetString("2.5.29.17", false, san);
    }

    /** The library only builds self-signed certificates as roots, so a self-signed server is a root too. */
    private static X509Bundle selfSigned(CertificateBuilder builder, String dnsName) throws Exception {
        return server(builder, dnsName).setIsCertificateAuthority(true).buildSelfSigned();
    }

    private static CertificateBuilder server(CertificateBuilder builder, String dnsName) {
        return builder.subject("CN=" + dnsName).addSanDnsName(dnsName);
    }

    /** Writes the bundle's chain and PKCS#8 key to the two files, replacing their content. */
    static void write(X509Bundle bundle, Path certFile, Path keyFile) throws IOException {
        Files.writeString(certFile, bundle.getCertificatePathPEM());
        Files.writeString(keyFile, bundle.getPrivateKeyPEM());
    }

    static Path writeCa(X509Bundle ca, Path file) throws IOException {
        return Files.writeString(file, ca.getRootCertificatePEM());
    }
}
