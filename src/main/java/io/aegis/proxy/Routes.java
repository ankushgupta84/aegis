package io.aegis.proxy;

import io.aegis.http.UriNormalizer;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Finds the route for a request: the first in configuration order whose host and path prefix fit.
 * Routing needs the host and path before the request can be parsed (the parse takes the route's
 * body scan limit), so this reads the two values from the raw request itself.
 */
final class Routes {

    private final List<Route> routes;

    Routes(List<Route> routes) {
        this.routes = List.copyOf(routes);
    }

    List<Route> all() {
        return routes;
    }

    /** @param hostHeader the Host header value, or null; @param rawTarget the request target as sent */
    Optional<Route> match(String hostHeader, String rawTarget) {
        String host = hostWithoutPort(hostHeader);
        int question = rawTarget.indexOf('?');
        String path = UriNormalizer.normalizePath(question < 0 ? rawTarget : rawTarget.substring(0, question));
        return routes.stream()
                .filter(route -> hostMatches(route.policy().host(), host))
                .filter(route -> path.startsWith(route.policy().pathPrefix()))
                .findFirst();
    }

    /** Same rules as {@code ParsedRequest.host()}: lowercase, port removed, IPv6 brackets kept. */
    private static String hostWithoutPort(String hostHeader) {
        if (hostHeader == null) {
            return "";
        }
        String host = hostHeader.strip().toLowerCase(Locale.ROOT);
        int colon = host.lastIndexOf(':');
        return colon > host.lastIndexOf(']') ? host.substring(0, colon) : host;
    }

    private static boolean hostMatches(String configured, String host) {
        if (configured.equals("*")) {
            return true;
        }
        if (configured.startsWith("*.")) {
            String suffix = configured.substring(1);
            return host.endsWith(suffix) && host.indexOf('.') == host.length() - suffix.length();
        }
        return configured.equals(host);
    }
}
