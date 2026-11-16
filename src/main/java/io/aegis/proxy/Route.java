package io.aegis.proxy;

import io.aegis.lb.LoadBalancer;
import io.aegis.policy.RoutePolicy;
import io.aegis.waf.Waf;

/** One route with everything built for it at startup: its WAF, its load balancer, its backend connections. */
record Route(RoutePolicy policy, Waf waf, LoadBalancer balancer, UpstreamClient upstream) {

    String name() {
        return policy.name();
    }
}
