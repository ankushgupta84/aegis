package io.aegis.observe;

/**
 * What a log may say about a request body: how long it was and its SHA-256, enough to correlate
 * and compare bodies without keeping their content.
 *
 * @param length    size in bytes
 * @param sha256Hex lowercase hex digest
 */
public record BodySummary(long length, String sha256Hex) {
}
