package io.aegis.proxy;

import io.aegis.observe.BodySummary;
import io.aegis.waf.WafVerdict;
import java.net.InetAddress;

/**
 * Everything one request learns on its way through the proxy, collected so a single {@code request}
 * event and the metrics can be written when it ends. A plain data bag touched only by the
 * request's event-loop thread, so it needs no accessors or locks.
 */
final class RequestRecord {

    final String id = RequestIds.next();
    final long startNanos = System.nanoTime();
    final InetAddress peer;

    InetAddress clientIp;
    String method;
    String rawTarget;
    String host;
    String userAgent;
    String routeName = "none";
    Decision decision = Decision.ALLOWED;
    int status;
    String reason;
    WafVerdict verdict;
    BodySummary blockedBody;
    String backend;
    boolean retried;
    long requestBytes;
    long responseBytes;
    long upstreamNanos;

    RequestRecord(InetAddress peer) {
        this.peer = peer;
    }
}
