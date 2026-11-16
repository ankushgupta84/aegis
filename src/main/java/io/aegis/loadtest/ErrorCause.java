package io.aegis.loadtest;

import io.netty.handler.codec.DecoderException;
import java.io.IOException;
import javax.net.ssl.SSLException;

/** Why a request produced no response. Each failed request is counted under exactly one cause. */
public enum ErrorCause {
    CONNECT_FAILURE,
    TLS_FAILURE,
    TIMEOUT,
    CONNECTION_RESET,
    CONNECTION_CLOSED,
    PROTOCOL_ERROR,
    UNEXPECTED;

    /** Maps an exception raised on an established channel to a cause. */
    static ErrorCause of(Throwable failure) {
        for (Throwable t = failure; t != null; t = t.getCause()) {
            if (t instanceof SSLException) {
                return TLS_FAILURE;
            }
        }
        if (failure instanceof DecoderException) {
            return PROTOCOL_ERROR;
        }
        if (failure instanceof IOException) {
            return CONNECTION_RESET;
        }
        return UNEXPECTED;
    }
}
