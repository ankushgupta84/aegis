package io.aegis.policy;

/** Where one backend listens. */
public record BackendAddress(String host, int port) {

    @Override
    public String toString() {
        return host + ":" + port;
    }
}
