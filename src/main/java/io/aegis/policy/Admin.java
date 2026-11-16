package io.aegis.policy;

/**
 * The admin endpoint: {@code /metrics} and {@code /healthz}. It has no authentication, so it
 * should stay bound to localhost.
 */
public record Admin(boolean enabled, String bindAddress, int port) {
}
