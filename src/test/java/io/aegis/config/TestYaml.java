package io.aegis.config;

import java.util.List;

/** Small configurations for tests, so each test shows only what it is about. */
final class TestYaml {
    /** The least a valid file needs: a profile, plain HTTP, and one route. */
    static final String MINIMAL = """
            profile: balanced
            listener:
              tls: false
            routes:
              - name: web
                backends: [127.0.0.1:9001]
            """;

    private TestYaml() {
    }

    /** {@link #MINIMAL} without its routes, followed by {@code extra} top-level YAML. */
    static String withoutRoutes(String extra) {
        return MINIMAL.substring(0, MINIMAL.indexOf("routes:")) + extra;
    }

    /** {@link #MINIMAL} followed by {@code extra} top-level YAML. */
    static String plus(String extra) {
        return MINIMAL + extra;
    }

    /** A profile, plain HTTP, and one route whose YAML body (indented four spaces) is {@code routeBody}. */
    static String route(String routeBody) {
        return "profile: balanced\nlistener:\n  tls: false\nroutes:\n  - name: web\n    backends: [127.0.0.1:9001]\n"
                + routeBody.indent(4);
    }

    static List<String> problemsOf(String yaml) {
        try {
            ConfigLoader.parse(yaml);
        } catch (ConfigException e) {
            return e.problems();
        }
        throw new AssertionError("Expected the configuration to be rejected");
    }
}
