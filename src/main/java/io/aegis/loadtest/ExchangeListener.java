package io.aegis.loadtest;

/** Receives the outcome of one request on a connection; called on that connection's event loop. */
interface ExchangeListener {

    void completed(int status);

    void failed(ErrorCause cause);
}
