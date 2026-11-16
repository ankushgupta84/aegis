package io.aegis.proxy;

import static org.assertj.core.api.Assertions.assertThat;

import io.aegis.policy.RoutePolicy;
import java.util.List;
import org.junit.jupiter.api.Test;

class RoutesTest {

    private final Routes routes = new Routes(List.of(
            route("admin", "*", "/admin"),
            route("shop", "shop.example.com", "/"),
            route("tenants", "*.example.com", "/"),
            route("public", "*", "/")));

    @Test
    void theFirstRouteWhoseHostAndPrefixFitWins() {
        assertThat(matched("other.test", "/index.html")).isEqualTo("public");
        assertThat(matched("other.test", "/admin/users")).isEqualTo("admin");
        assertThat(matched("Shop.Example.com:8443", "/cart")).isEqualTo("shop");
    }

    @Test
    void aWildcardHostMatchesExactlyOneLabel() {
        assertThat(matched("a.example.com", "/")).isEqualTo("tenants");
        assertThat(matched("a.b.example.com", "/")).isEqualTo("public");
        assertThat(matched("example.com", "/")).isEqualTo("public");
    }

    @Test
    void aPathThatClimbsIntoAnotherRouteIsJudgedByThatRoute() {
        assertThat(matched("other.test", "/static/../admin/users")).isEqualTo("admin");
        assertThat(matched("other.test", "/static/%2e%2e/admin")).isEqualTo("admin");
        assertThat(matched("other.test", "/static/..%2Fadmin?x=1")).isEqualTo("admin");
    }

    @Test
    void aPathThatClimbsOutOfARouteNoLongerMatchesIt() {
        assertThat(matched("other.test", "/admin/../index.html")).isEqualTo("public");
    }

    @Test
    void aRequestWithNoHostHeaderCanOnlyMatchAnyHostRoutes() {
        assertThat(matched(null, "/cart")).isEqualTo("public");
    }

    @Test
    void noRouteFitsWhenNothingMatches() {
        Routes onlyShop = new Routes(List.of(route("shop", "shop.example.com", "/")));

        assertThat(onlyShop.match("other.test", "/")).isEmpty();
    }

    private String matched(String host, String target) {
        return routes.match(host, target).orElseThrow().name();
    }

    /** Lookup reads only the policy's host and prefix, so the route's collaborators are left out. */
    private static Route route(String name, String host, String pathPrefix) {
        return new Route(new RoutePolicy(name, host, pathPrefix, null, null), null, null, null);
    }
}
