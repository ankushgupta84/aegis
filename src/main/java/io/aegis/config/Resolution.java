package io.aegis.config;

import io.aegis.policy.AegisConfig;

/** A loaded configuration together with the record of where each of its values came from. */
record Resolution(AegisConfig config, Ledger ledger) {
}
