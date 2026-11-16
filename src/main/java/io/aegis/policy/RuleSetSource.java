package io.aegis.policy;

import java.nio.file.Path;

/**
 * A Suricata rule file to import, unchanged.
 *
 * @param name        how routes and exemptions refer to this rule set
 * @param defaultMode the mode its rules run in unless a route says otherwise
 */
public record RuleSetSource(String name, Path file, RuleMode defaultMode) {
}
