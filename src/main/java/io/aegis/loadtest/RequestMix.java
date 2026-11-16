package io.aegis.loadtest;

import java.util.List;
import java.util.Random;

/**
 * Draws the kind of each request from the configured shares. A seeded generator makes the
 * sequence repeatable, so a direct run and a through-the-proxy run see the same traffic.
 */
final class RequestMix {

    /** Percent-encoded as a browser would send them; a WAF must decode before it matches. */
    static final List<String> ATTACK_URIS = List.of(
            "/search?q=1%27%20OR%20%271%27%3D%271",
            "/item?id=1%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--",
            "/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
            "/download?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd",
            "/static/..%2F..%2F..%2Fetc%2Fpasswd");

    private static final String BENIGN_URI = "/index.html";

    private final LoadTestOptions options;
    private final Random random;

    RequestMix(LoadTestOptions options) {
        this.options = options;
        this.random = new Random(options.seed());
    }

    RequestSpec next() {
        boolean post = random.nextDouble() < options.postShare();
        int bodyBytes = post ? randomBodySize() : 0;
        boolean attack = random.nextDouble() < options.attackShare();
        String uri = attack ? ATTACK_URIS.get(random.nextInt(ATTACK_URIS.size())) : BENIGN_URI;
        boolean newConnection = random.nextDouble() < options.newConnectionShare();
        return new RequestSpec(post, bodyBytes, uri, attack, newConnection);
    }

    private int randomBodySize() {
        int span = options.bodyMaxBytes() - options.bodyMinBytes() + 1;
        return options.bodyMinBytes() + random.nextInt(span);
    }
}
