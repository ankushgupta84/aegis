package io.aegis.config;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * Thrown when a configuration cannot be loaded. It carries every problem found, not just the
 * first, so an operator fixes the file in one pass.
 */
public final class ConfigException extends RuntimeException {
    private final List<String> problems;

    ConfigException(List<String> problems) {
        super(describe(problems));
        this.problems = List.copyOf(problems);
    }

    /** Each problem as one plain-language sentence that names where it is. */
    public List<String> problems() {
        return problems;
    }

    private static String describe(List<String> problems) {
        String count = problems.size() == 1 ? "1 problem" : problems.size() + " problems";
        String numbered = IntStream.range(0, problems.size())
                .mapToObj(i -> "  " + (i + 1) + ". " + problems.get(i))
                .collect(Collectors.joining("\n"));
        return "The configuration has " + count + ":\n" + numbered;
    }
}
