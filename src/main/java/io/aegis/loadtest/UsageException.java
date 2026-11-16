package io.aegis.loadtest;

/** A command line the user got wrong; the message says how, and the tool prints it with the usage text. */
public final class UsageException extends RuntimeException {

    public UsageException(String message) {
        super(message);
    }
}
