package io.aegis.policy;

import java.nio.file.Path;
import java.util.List;

/**
 * Where events are written and what is safe to keep in them.
 *
 * @param directory           the folder for {@code aegis.log} and its rotated predecessors
 * @param rotateAtBytes       a log file is rotated once it reaches this size
 * @param keepFiles           how many rotated files to keep
 * @param loggedQueryParams   query parameters whose values may be logged; all others are masked
 */
public record LogSettings(Path directory, long rotateAtBytes, int keepFiles, List<String> loggedQueryParams) {

    public LogSettings {
        loggedQueryParams = List.copyOf(loggedQueryParams);
    }
}
