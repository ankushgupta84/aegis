package io.aegis.tls;

import io.aegis.plugin.CertificateProvider.Material;
import io.netty.handler.ssl.ApplicationProtocolConfig;
import io.netty.handler.ssl.ApplicationProtocolConfig.Protocol;
import io.netty.handler.ssl.ApplicationProtocolConfig.SelectedListenerFailureBehavior;
import io.netty.handler.ssl.ApplicationProtocolConfig.SelectorFailureBehavior;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLException;

/** Builds the server-side {@link SslContext} for one certificate. */
final class ServerContexts {

    /** Aegis speaks HTTP/1.1 to clients; advertising nothing else keeps clients off protocols it cannot serve. */
    private static final ApplicationProtocolConfig ALPN = new ApplicationProtocolConfig(
            Protocol.ALPN,
            SelectorFailureBehavior.NO_ADVERTISE,
            SelectedListenerFailureBehavior.ACCEPT,
            "http/1.1");

    private ServerContexts() {
    }

    static SslContext create(Material material) throws SSLException {
        return SslContextBuilder.forServer(material.key(), material.chain().toArray(new X509Certificate[0]))
                .sslProvider(SslProvider.JDK)
                .protocols("TLSv1.3", "TLSv1.2")
                .applicationProtocolConfig(ALPN)
                .build();
    }
}
