package io.aegis.proxy;

import io.aegis.firewall.Firewall;
import io.aegis.firewall.FirewallVerdict;
import io.aegis.http.ClientIpResolver;
import io.aegis.http.FramingCheck;
import io.aegis.http.ParsedRequest;
import io.aegis.waf.WafVerdict;
import io.netty.buffer.ByteBufUtil;
import io.netty.handler.codec.TooLongFrameException;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.TooLongHttpHeaderException;
import io.netty.handler.codec.http.TooLongHttpLineException;
import java.net.InetAddress;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Stages 1 to 8 of the data path: everything that decides, before any backend is touched, whether a
 * request may go on. It does no I/O and writes no response; it returns either the refusal or the
 * route to forward to, and records what it learned in the {@link RequestRecord}.
 */
final class Screening {

    /** The outcome of screening. */
    sealed interface Result permits Refused, Admitted {
    }

    record Refused(Refusal refusal) implements Result {
    }

    record Admitted(Route route) implements Result {
    }

    private final ClientIpResolver clientIps;
    private final Firewall firewall;
    private final Routes routes;
    private final Telemetry telemetry;

    Screening(ClientIpResolver clientIps, Firewall firewall, Routes routes, Telemetry telemetry) {
        this.clientIps = clientIps;
        this.firewall = firewall;
        this.routes = routes;
        this.telemetry = telemetry;
    }

    Result screen(FullHttpRequest request, RequestRecord record) {
        if (request.decoderResult().isFailure()) {
            return new Refused(decodeFailure(request.decoderResult().cause()));
        }
        record.method = request.method().name();
        record.rawTarget = request.uri();
        record.host = request.headers().get("Host");
        record.userAgent = request.headers().get("User-Agent");

        List<Map.Entry<String, String>> headers = request.headers().entries();
        Optional<Refusal> malformed = malformed(request, headers);
        if (malformed.isPresent()) {
            return new Refused(malformed.get());
        }
        record.clientIp = clientIps.resolve(record.peer, request.headers().getAll("X-Forwarded-For"));
        Optional<Refusal> denied = firewallRefusal(record.clientIp);
        if (denied.isPresent()) {
            return new Refused(denied.get());
        }
        Optional<Route> route = routes.match(record.host, request.uri());
        if (route.isEmpty()) {
            return new Refused(Refusal.noRoute());
        }
        record.routeName = route.get().name();
        return inspect(request, headers, route.get(), record);
    }

    private static Refusal decodeFailure(Throwable cause) {
        if (cause instanceof TooLongHttpLineException) {
            return Refusal.uriTooLong();
        }
        if (cause instanceof TooLongHttpHeaderException) {
            return Refusal.headersTooLarge();
        }
        String detail = cause instanceof TooLongFrameException ? "frame too long" : String.valueOf(cause.getMessage());
        return Refusal.badRequest("malformed request: " + detail);
    }

    private static Optional<Refusal> malformed(FullHttpRequest request, List<Map.Entry<String, String>> headers) {
        Optional<String> framing = FramingCheck.violation(headers);
        if (framing.isPresent()) {
            return Optional.of(Refusal.badRequest(framing.get()));
        }
        if (request.method().equals(HttpMethod.CONNECT)) {
            return Optional.of(Refusal.methodNotAllowed("CONNECT"));
        }
        if (request.headers().contains("Upgrade")) {
            return Optional.of(Refusal.upgradeNotSupported());
        }
        if (!isOriginForm(request.uri())) {
            return Optional.of(Refusal.badRequest("request target must start with '/' and hold only printable ASCII"));
        }
        return Optional.empty();
    }

    /**
     * Only origin-form targets are served, and only ASCII ones: a byte above 0x7F would reach the
     * backend as a different byte from the one the WAF inspected, so the disagreement is refused
     * instead of resolved.
     */
    private static boolean isOriginForm(String target) {
        return target.startsWith("/") && target.chars().allMatch(c -> c > 0x20 && c < 0x7F);
    }

    private Optional<Refusal> firewallRefusal(InetAddress client) {
        FirewallVerdict verdict = firewall.check(client);
        telemetry.metrics().firewallDecided(verdict);
        return switch (verdict) {
            case ALLOW -> Optional.empty();
            case DENY_LISTED, NOT_ALLOW_LISTED -> Optional.of(Refusal.firewallDenied(verdict.name().toLowerCase(Locale.ROOT)));
            case RATE_LIMITED -> Optional.of(Refusal.rateLimited());
        };
    }

    private Result inspect(FullHttpRequest request, List<Map.Entry<String, String>> headers, Route route,
            RequestRecord record) {
        byte[] body = ByteBufUtil.getBytes(request.content());
        ParsedRequest parsed;
        try {
            parsed = ParsedRequest.of(request.method().name(), request.uri(), request.protocolVersion().text(),
                    headers, body, route.policy().waf().knobs().bodyScanLimitBytes());
        } catch (IllegalArgumentException e) {
            return new Refused(Refusal.badRequest("request text is not one byte per character: " + e.getMessage()));
        }
        long started = System.nanoTime();
        WafVerdict verdict = route.waf().evaluate(parsed, record.clientIp, parsed.bodyTruncated());
        telemetry.metrics().wafInspected(System.nanoTime() - started);
        record.verdict = verdict;
        verdict.hits().forEach(telemetry.metrics()::ruleHit);
        verdict.gaps().forEach(gap -> telemetry.metrics().inspectionGap(gap, verdict.blocked()));
        if (verdict.blocked()) {
            record.blockedBody = telemetry.redactor().body(body);
            return new Refused(Refusal.wafBlocked());
        }
        return new Admitted(route);
    }
}
