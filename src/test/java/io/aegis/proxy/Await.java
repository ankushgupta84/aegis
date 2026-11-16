package io.aegis.proxy;

import java.util.function.BooleanSupplier;

/** Polls for a condition with a deadline, so tests never rely on a fixed sleep for correctness. */
final class Await {

    private Await() {
    }

    static void until(String what, BooleanSupplier condition) throws InterruptedException {
        long deadline = System.nanoTime() + 5_000_000_000L;
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("Gave up waiting for " + what);
            }
            Thread.sleep(5);
        }
    }
}
