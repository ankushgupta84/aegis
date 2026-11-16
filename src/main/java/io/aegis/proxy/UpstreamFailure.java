package io.aegis.proxy;

import io.netty.handler.ssl.SslHandshakeTimeoutException;
import io.netty.channel.ConnectTimeoutException;
import javax.net.ssl.SSLException;

/** Why an attempt to get an answer from a backend failed; the label is used in logs and metrics. */
enum UpstreamFailure {
    CONNECT_ERROR("connect_error", false),
    CONNECT_TIMEOUT("connect_timeout", true),
    TLS_ERROR("tls_error", false),
    RESPONSE_TIMEOUT("response_timeout", true),
    CONNECTION_RESET("reset", false),
    INVALID_RESPONSE("invalid_response", false),
    SERVER_ERROR("server_error", false);

    private final String label;
    private final boolean timeout;

    UpstreamFailure(String label, boolean timeout) {
        this.label = label;
        this.timeout = timeout;
    }

    String label() {
        return label;
    }

    Decision decision() {
        return timeout ? Decision.UPSTREAM_TIMEOUT : Decision.UPSTREAM_FAILED;
    }

    Refusal refusal() {
        return timeout ? Refusal.upstreamTimeout(label) : Refusal.upstreamFailed(label);
    }

    /** Classifies a failure to connect, which includes the TLS handshake. */
    static UpstreamFailure ofConnect(Throwable cause) {
        if (cause instanceof ConnectTimeoutException || cause instanceof SslHandshakeTimeoutException) {
            return CONNECT_TIMEOUT;
        }
        for (Throwable t = cause; t != null; t = t.getCause()) {
            if (t instanceof SSLException) {
                return TLS_ERROR;
            }
        }
        return CONNECT_ERROR;
    }
}
