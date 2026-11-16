package io.aegis.config;

import io.aegis.policy.AegisConfig;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/**
 * Loads the YAML configuration into the validated, fully resolved {@link AegisConfig} the rest of
 * Aegis reads. Everything wrong with the file is reported at once, in plain language; nothing is
 * ignored and no invalid value is replaced by a default.
 *
 * <p>Relative file names are kept as written and resolve against the working directory when used.
 * The loader does not open the files they name: the components that read them fail loudly.
 */
public final class ConfigLoader {
    private ConfigLoader() {
    }

    /** @throws ConfigException if the file cannot be read or holds any problem */
    public static AegisConfig load(Path yamlFile) {
        return parse(readText(yamlFile));
    }

    /** @throws ConfigException if the text holds any problem */
    public static AegisConfig parse(String yaml) {
        return ConfigReader.read(yaml).config();
    }

    static String readText(Path yamlFile) {
        try {
            return Files.readString(yamlFile);
        } catch (IOException e) {
            throw new ConfigException(List.of("Cannot read the configuration file " + yamlFile + ": " + e));
        }
    }
}
