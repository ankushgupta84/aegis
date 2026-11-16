package io.aegis;

import io.aegis.config.ConfigException;
import io.aegis.config.ConfigExplainer;
import io.aegis.config.ConfigLoader;
import io.aegis.policy.AegisConfig;
import io.aegis.proxy.AegisServer;
import io.aegis.proxy.ConfigCheck;
import io.aegis.proxy.StartupException;
import java.nio.file.Path;

/** Command line entry point: {@code run}, {@code explain}, and {@code check}. The logic lives in {@code io.aegis.proxy}. */
public final class Aegis {

    private static final String USAGE = "Usage: aegis run|explain|check <config.yaml>";
    private static final int USAGE_OR_CONFIG_ERROR = 2;
    private static final int STARTUP_FAILURE = 1;

    private Aegis() {
    }

    public static void main(String[] args) throws InterruptedException {
        if (args.length != 2 || !(args[0].equals("run") || args[0].equals("explain") || args[0].equals("check"))) {
            System.err.println(USAGE);
            System.exit(USAGE_OR_CONFIG_ERROR);
        }
        Path file = Path.of(args[1]);
        try {
            switch (args[0]) {
                case "explain" -> System.out.print(ConfigExplainer.explain(file));
                case "check" -> System.out.print(ConfigCheck.report(ConfigLoader.load(file)));
                default -> run(ConfigLoader.load(file));
            }
        } catch (ConfigException e) {
            System.err.println(e.getMessage());
            System.exit(USAGE_OR_CONFIG_ERROR);
        } catch (StartupException e) {
            System.err.println("Cannot start: " + e.getMessage());
            System.exit(STARTUP_FAILURE);
        }
    }

    /** Serves until SIGTERM or SIGINT, then drains and exits 0 (the JVM would otherwise exit 143). */
    private static void run(AegisConfig config) throws InterruptedException {
        AegisServer server = AegisServer.start(config);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            server.close();
            Runtime.getRuntime().halt(0);
        }, "aegis-shutdown"));
        System.out.println("aegis listening on port " + server.port());
        Thread.currentThread().join();
    }
}
