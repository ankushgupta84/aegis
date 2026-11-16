package io.aegis.proxy;

import io.aegis.firewall.Firewall;
import io.aegis.http.ClientIpResolver;
import io.aegis.lb.LoadBalancer;
import io.aegis.observe.Event;
import io.aegis.observe.EventLog;
import io.aegis.observe.Metrics;
import io.aegis.observe.Redactor;
import io.aegis.policy.AegisConfig;
import io.aegis.policy.RoutePolicy;
import io.aegis.rules.RuleSet;
import io.aegis.rules.RuleStatus;
import io.aegis.tls.CertificateEvent;
import io.aegis.tls.ServerTls;
import io.aegis.tls.UpstreamTlsContexts;
import io.aegis.waf.RuleEngine;
import io.aegis.waf.Waf;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.handler.ssl.SslContext;
import java.net.InetSocketAddress;
import java.time.Clock;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * The composition root: builds every part from a validated configuration, binds the listeners,
 * and owns their lifecycle. Used by {@code aegis run} and by end-to-end tests.
 *
 * <p>Startup is all or nothing. Parts are opened in dependency order and each one that opens
 * registers how to close it; if any step fails, everything already open is closed in reverse
 * order and the failure propagates, so Aegis never runs half-configured.
 */
public final class AegisServer implements AutoCloseable {

    private static final int SERIES_CAP_PER_METRIC = 10_000;
    private static final int BACKLOG = 1024;
    private static final long SHUTDOWN_TIMEOUT_SECONDS = 5;

    private final AegisConfig config;
    private final EventLog events;
    private final Drain drain;
    private final Channel listener;
    private final EventLoopGroup workers;
    private final Optional<AdminServer> admin;
    private final Optional<ServerTls> serverTls;
    private final AtomicBoolean closed = new AtomicBoolean();

    private AegisServer(AegisConfig config, EventLog events, Drain drain, Channel listener, EventLoopGroup workers,
            Optional<AdminServer> admin, Optional<ServerTls> serverTls) {
        this.config = config;
        this.events = events;
        this.drain = drain;
        this.listener = listener;
        this.workers = workers;
        this.admin = admin;
        this.serverTls = serverTls;
    }

    /**
     * Starts serving. The ports in the configuration may be 0; {@link #port()} and
     * {@link #adminPort()} report the ones actually bound.
     *
     * @throws StartupException if a rule file cannot be read, a backend host cannot be resolved, or a port cannot be bound
     * @throws RuntimeException for any other failure to open a part, such as a bad certificate
     */
    public static AegisServer start(AegisConfig config) {
        Deque<Runnable> undo = new ArrayDeque<>();
        try {
            return open(config, undo);
        } catch (Throwable failure) {
            while (!undo.isEmpty()) {
                try {
                    undo.pop().run();
                } catch (RuntimeException closing) {
                    failure.addSuppressed(closing);
                }
            }
            throw failure;
        }
    }

    private static AegisServer open(AegisConfig config, Deque<Runnable> undo) {
        List<RuleSet> ruleSets = RuleSetLoader.load(config.ruleSets());
        RuleEngine engine = RuleEngine.compile(ruleSets);

        EventLog events = new EventLog(config.log(), List.of(), Clock.systemUTC());
        undo.push(events::close);
        Metrics rawMetrics = new Metrics(SERIES_CAP_PER_METRIC);
        ProxyMetrics metrics = new ProxyMetrics(rawMetrics);
        Telemetry telemetry = new Telemetry(events, metrics, new Redactor(config.log()));
        Firewall firewall = new Firewall(config.firewall(), System::nanoTime);
        metrics.registerGauges(firewall, events);
        ruleSets.forEach(set -> reportRuleSet(set, telemetry));

        Transport transport = Transport.best();
        Routes routes = buildRoutes(config, engine, transport, telemetry);
        Screening screening = new Screening(new ClientIpResolver(config.clientIp()), firewall, routes, telemetry);

        Optional<ServerTls> serverTls = config.listener().tls()
                ? Optional.of(ServerTls.open(config.tlsHosts(), event -> reportCertificate(event, telemetry)))
                : Optional.empty();
        serverTls.ifPresent(tls -> undo.push(tls::close));

        Drain drain = new Drain();
        EventLoopGroup workers = transport.newGroup(Runtime.getRuntime().availableProcessors());
        undo.push(() -> workers.shutdownGracefully(0, SHUTDOWN_TIMEOUT_SECONDS, TimeUnit.SECONDS).syncUninterruptibly());
        Channel listener = bind(config, workers, transport,
                new ClientChannelInitializer(config.listener(), serverTls, screening, telemetry, drain));
        undo.push(() -> listener.close().syncUninterruptibly());

        Optional<AdminServer> admin = config.admin().enabled()
                ? Optional.of(AdminServer.start(config.admin(), rawMetrics, transport))
                : Optional.empty();
        admin.ifPresent(a -> undo.push(a::close));

        AegisServer server = new AegisServer(config, events, drain, listener, workers, admin, serverTls);
        events.write(Event.of("startup")
                .with("profile", config.profile())
                .with("port", server.port())
                .with("admin_port", admin.isPresent() ? server.adminPort() : null)
                .with("tls", config.listener().tls())
                .with("routes", routes.all().stream().map(Route::name).toList())
                .with("rules", engine.ruleCount()));
        return server;
    }

    /** Netty rethrows a bind failure as a checked exception without declaring it; turn it into a startup failure. */
    private static Channel bind(AegisConfig config, EventLoopGroup workers, Transport transport,
            ClientChannelInitializer initializer) {
        try {
            return new ServerBootstrap()
                    .group(workers)
                    .channel(transport.serverChannel())
                    .option(ChannelOption.SO_BACKLOG, BACKLOG)
                    .childOption(ChannelOption.TCP_NODELAY, true)
                    .childHandler(initializer)
                    .bind(config.listener().bindAddress(), config.listener().port())
                    .syncUninterruptibly()
                    .channel();
        } catch (Exception e) {
            throw new StartupException("Cannot listen on " + config.listener().bindAddress() + ":"
                    + config.listener().port() + ": " + e.getMessage(), e);
        }
    }

    private static Routes buildRoutes(AegisConfig config, RuleEngine engine, Transport transport, Telemetry telemetry) {
        List<Route> routes = new ArrayList<>();
        for (RoutePolicy policy : config.routes()) {
            Waf waf = new Waf(engine, policy.waf(), System::nanoTime, error -> telemetry.events().write(
                    Event.of("engine_error")
                            .with("route", policy.name())
                            .with("exception", error.getClass().getName())
                            .with("message", error.getMessage())));
            LoadBalancer balancer = new LoadBalancer(policy.upstream().backends(), policy.upstream().health(), System::nanoTime);
            Optional<SslContext> tls = policy.upstream().tls().enabled()
                    ? Optional.of(UpstreamTlsContexts.clientContext(policy.upstream().tls()))
                    : Optional.empty();
            routes.add(new Route(policy, waf, balancer, new UpstreamClient(transport, policy.upstream(), tls)));
        }
        return new Routes(routes);
    }

    private static void reportRuleSet(RuleSet set, Telemetry telemetry) {
        telemetry.metrics().ruleSetLoaded(set);
        telemetry.events().write(Event.of("rule_set_loaded")
                .with("rule_set", set.name())
                .with("active", set.count(RuleStatus.ACTIVE))
                .with("not_applicable", set.count(RuleStatus.NOT_APPLICABLE))
                .with("unsupported", set.count(RuleStatus.UNSUPPORTED)));
    }

    private static void reportCertificate(CertificateEvent event, Telemetry telemetry) {
        telemetry.metrics().certificate(event);
        telemetry.events().write(Event.of("certificate")
                .with("hostname", event.hostname())
                .with("kind", event.kind().name().toLowerCase(Locale.ROOT))
                .with("detail", event.detail()));
    }

    /** The port the proxy listens on. */
    public int port() {
        return ((InetSocketAddress) listener.localAddress()).getPort();
    }

    /** The port of the admin listener. @throws IllegalStateException if the admin listener is disabled */
    public int adminPort() {
        return admin.orElseThrow(() -> new IllegalStateException("The admin listener is disabled (admin.enabled: false)")).port();
    }

    /**
     * Stops accepting, lets requests in flight finish for up to {@code listener.drain_timeout}, then
     * closes everything. Safe to call more than once.
     */
    @Override
    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        listener.close().syncUninterruptibly();
        drain.begin();
        int unfinished = drain.awaitIdle(config.listener().drainTimeout());
        events.write(Event.of("shutdown").with("requests_cut_off", unfinished));
        workers.shutdownGracefully(0, SHUTDOWN_TIMEOUT_SECONDS, TimeUnit.SECONDS).syncUninterruptibly();
        admin.ifPresent(AdminServer::close);
        serverTls.ifPresent(ServerTls::close);
        events.close();
    }
}
