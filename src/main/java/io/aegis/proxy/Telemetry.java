package io.aegis.proxy;

import io.aegis.observe.EventLog;
import io.aegis.observe.Redactor;

/** The three outlets every stage reports to, passed together so stages do not take three arguments each. */
record Telemetry(EventLog events, ProxyMetrics metrics, Redactor redactor) {
}
