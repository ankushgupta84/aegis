package io.aegis.firewall;

import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

/** A clock that moves only when a test says so. */
final class FakeClock implements LongSupplier {

    private final AtomicLong nanos = new AtomicLong();

    void advanceNanos(long delta) {
        nanos.addAndGet(delta);
    }

    @Override
    public long getAsLong() {
        return nanos.get();
    }
}
