package io.aegis.loadtest;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * The {@code --name value} pairs of a command line, checked against the flags a tool accepts.
 * Unknown flags, repeated flags, and missing values are errors, so a typo never silently
 * falls back to a default.
 */
final class FlagArguments {

    private final Map<String, String> values = new HashMap<>();

    FlagArguments(String[] args, Set<String> accepted) {
        for (int i = 0; i < args.length; i += 2) {
            String flag = args[i];
            if (!flag.startsWith("--") || !accepted.contains(flag)) {
                throw new UsageException("unknown argument: " + flag);
            }
            if (i + 1 >= args.length) {
                throw new UsageException(flag + " needs a value");
            }
            if (values.put(flag, args[i + 1]) != null) {
                throw new UsageException(flag + " given twice");
            }
        }
    }

    Optional<String> get(String flag) {
        return Optional.ofNullable(values.get(flag));
    }

    String get(String flag, String defaultValue) {
        return values.getOrDefault(flag, defaultValue);
    }

    String require(String flag) {
        return get(flag).orElseThrow(() -> new UsageException(flag + " is required"));
    }
}
