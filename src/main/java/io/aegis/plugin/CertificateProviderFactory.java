package io.aegis.plugin;

import java.util.Map;

/**
 * Creates certificate providers of one {@code type}. Aegis discovers factories with
 * {@link java.util.ServiceLoader}, so a customer's provider is registered the same way as a
 * built-in one.
 */
public interface CertificateProviderFactory {

    /** The value of {@code type} in configuration that selects this factory, e.g. {@code file_watch}. */
    String type();

    /**
     * @param settings the provider's own settings, exactly as written in configuration
     * @throws IllegalArgumentException with a plain-language message when a setting is missing or wrong
     */
    CertificateProvider create(Map<String, String> settings);
}
