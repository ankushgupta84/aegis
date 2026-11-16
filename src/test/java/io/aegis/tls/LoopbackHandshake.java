package io.aegis.tls;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.handler.ssl.SniHandler;
import io.netty.handler.ssl.SslContext;
import io.netty.util.Mapping;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLPeerUnverifiedException;

/**
 * The outcome of a real TLS handshake between a Netty client and a server behind
 * {@link SniHandler}, with the bytes carried between two in-memory channels. No sockets, no
 * sleeps.
 *
 * @param failure what either side threw when the handshake failed; null on success
 */
record LoopbackHandshake(boolean succeeded, X509Certificate serverCertificate, String protocol, String alpn,
                         Throwable failure) {

    private static final int MAX_ROUNDS = 100;

    /** @param serverName the SNI name and the name the client verifies; null sends no SNI */
    static LoopbackHandshake run(Mapping<String, SslContext> server, SslContext client, String serverName) {
        var clientSsl = serverName == null
                ? client.newHandler(ByteBufAllocator.DEFAULT)
                : client.newHandler(ByteBufAllocator.DEFAULT, serverName, 443);
        var clientChannel = new EmbeddedChannel(clientSsl);
        var serverChannel = new EmbeddedChannel(new SniHandler(server));
        for (int round = 0; round < MAX_ROUNDS && !clientSsl.handshakeFuture().isDone(); round++) {
            var failure = carry(clientChannel, serverChannel);
            if (failure == null) {
                failure = carry(serverChannel, clientChannel);
            }
            if (failure != null) {
                return failed(failure);
            }
        }
        if (!clientSsl.handshakeFuture().isSuccess()) {
            return failed(clientSsl.handshakeFuture().cause());
        }
        try {
            var session = clientSsl.engine().getSession();
            var result = new LoopbackHandshake(true, (X509Certificate) session.getPeerCertificates()[0],
                    session.getProtocol(), clientSsl.applicationProtocol(), null);
            clientChannel.close();
            serverChannel.close();
            return result;
        } catch (SSLPeerUnverifiedException e) {
            throw new AssertionError(e);
        }
    }

    /** Moves everything {@code from} wrote to {@code to}; returns what {@code to} threw, or null. */
    private static Throwable carry(EmbeddedChannel from, EmbeddedChannel to) {
        from.runPendingTasks();
        for (ByteBuf bytes; (bytes = from.readOutbound()) != null; ) {
            try {
                to.writeInbound(bytes);
            } catch (RuntimeException rejected) {
                return rejected;
            }
        }
        to.runPendingTasks();
        return null;
    }

    private static LoopbackHandshake failed(Throwable failure) {
        return new LoopbackHandshake(false, null, null, null, failure);
    }
}
