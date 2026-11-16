package io.aegis.policy;

/**
 * The flat, fully resolved policy for one route. Profile, global, and route settings are merged
 * when configuration loads, so serving a request never walks an inheritance chain.
 *
 * @param host       the hostname this route serves, lowercase, or {@code *} for any
 * @param pathPrefix the path prefix this route serves; {@code /} matches everything
 */
public record RoutePolicy(String name, String host, String pathPrefix, WafPolicy waf, UpstreamPolicy upstream) {
}
