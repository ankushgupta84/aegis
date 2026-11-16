package io.aegis.policy;

import java.util.Map;

/**
 * The certificate Aegis presents for one hostname.
 *
 * @param hostname         the SNI name, lowercase; {@code *.example.com} matches one label
 * @param providerType     selects the certificate provider, e.g. {@code file_watch}
 * @param providerSettings the provider's own settings
 */
public record TlsHost(String hostname, TlsMode mode, String providerType, Map<String, String> providerSettings) {

    public TlsHost {
        providerSettings = Map.copyOf(providerSettings);
    }
}
