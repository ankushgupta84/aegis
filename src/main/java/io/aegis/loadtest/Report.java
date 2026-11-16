package io.aegis.loadtest;

import java.util.Map;

/**
 * The numbers of one run, measured phase only. Serialized as-is to JSON so a script can subtract
 * a direct run from a through-the-proxy run.
 *
 * @param label               free text naming the run
 * @param target              the URL under test
 * @param configuredRate      requests per second asked for
 * @param achievedRate        measured requests divided by the time from the first intended send to the last completion
 * @param measuredSeconds     length of that span
 * @param seed                seed of the request mix
 * @param connections         keep-alive connections configured
 * @param requests            measured requests, whatever their outcome
 * @param warmupRequests      requests sent before measuring began
 * @param responsesByStatus   responses by HTTP status code
 * @param attackRequests      measured requests that carried an attack payload
 * @param expectedAttackBlocks attack requests answered 403
 * @param otherNon2xx         non-2xx responses that are not an expected attack block
 * @param errorsByCause       requests with no response, by cause; every cause is listed
 * @param errors              total of errorsByCause
 * @param latencyMs           latency percentiles in milliseconds
 * @param maxQueueDepth       most requests that waited at once for a free connection
 */
public record Report(
        String label,
        String target,
        long configuredRate,
        double achievedRate,
        double measuredSeconds,
        long seed,
        int connections,
        long requests,
        long warmupRequests,
        Map<Integer, Long> responsesByStatus,
        long attackRequests,
        long expectedAttackBlocks,
        long otherNon2xx,
        Map<ErrorCause, Long> errorsByCause,
        long errors,
        LatencyMs latencyMs,
        int maxQueueDepth) {

    /** Latency percentiles in milliseconds. Errors enter at the timeout value. */
    public record LatencyMs(double p50, double p90, double p99, double p999, double max) {
    }
}
