package io.aegis.proxy;

/** Aegis cannot start, for a reason the operator can fix, such as an unreadable rule file. */
public final class StartupException extends RuntimeException {

    public StartupException(String message) {
        super(message);
    }

    public StartupException(String message, Throwable cause) {
        super(message, cause);
    }
}
