package io.aegis.config;

import java.nio.file.Path;
import java.util.stream.Collectors;

/**
 * Explains a configuration: the value in force for every knob and where it came from, then
 * everything that has been loosened and who answers for it. An operator reads this, or an AI
 * turns it into a story for a CISO, so the text is line-oriented and stable.
 *
 * <p>The explanation is built from the same resolution that {@link ConfigLoader} uses, never from
 * a second pass over the file.
 */
public final class ConfigExplainer {
    private ConfigExplainer() {
    }

    /** @throws ConfigException if the text holds any problem */
    public static String explain(String yaml) {
        Resolution resolution = ConfigReader.read(yaml);
        String knobs = resolution.ledger().entries().stream()
                .map(Ledger.Entry::line)
                .collect(Collectors.joining("\n"));
        return knobs + "\n\n" + LoosenedReport.of(resolution.config()) + "\n";
    }

    /** @throws ConfigException if the file cannot be read or holds any problem */
    public static String explain(Path yamlFile) {
        return explain(ConfigLoader.readText(yamlFile));
    }
}
