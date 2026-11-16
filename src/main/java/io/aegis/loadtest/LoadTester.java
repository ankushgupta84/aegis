package io.aegis.loadtest;

/**
 * An open-loop HTTP load generator.
 *
 * <p>Requests leave on a fixed schedule, one every {@code 1/rate} seconds, whether or not earlier
 * responses have come back. Each latency is measured from the request's <em>intended</em> send
 * time. A closed-loop generator, which sends the next request only after the previous response,
 * slows down exactly when the server does: the requests that would have met the stall are never
 * sent, so the stall barely appears in the percentiles. This is coordinated omission, and it
 * makes a tail-latency budget such as "added p99 under 10 ms" impossible to test honestly.
 * Open-loop sending with intended-time latency charges every request that was due during a stall
 * for the time it spent waiting.
 */
public final class LoadTester {

    private LoadTester() {
    }

    /** Runs the options to completion and returns the measured report. */
    public static Report run(LoadTestOptions options) throws Exception {
        return LoadRun.execute(options);
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 1 && args[0].equals("--help")) {
            System.out.print(LoadTestOptions.HELP);
            return;
        }
        LoadTestOptions options;
        try {
            options = LoadTestOptions.parse(args);
        } catch (UsageException e) {
            System.err.println("error: " + e.getMessage() + "\n\n" + LoadTestOptions.HELP);
            System.exit(2);
            return;
        }
        Report report = run(options);
        System.out.print(ReportText.format(report));
        if (options.jsonFile().isPresent()) {
            ReportJson.write(report, options.jsonFile().get());
        }
    }
}
