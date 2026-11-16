package io.aegis.loadtest;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.io.IOException;
import java.nio.file.Path;

/** Writes a {@link Report} as JSON, field names as in the record, for scripts that compare runs. */
final class ReportJson {

    private static final ObjectMapper MAPPER = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    private ReportJson() {
    }

    static void write(Report report, Path file) throws IOException {
        MAPPER.writeValue(file.toFile(), report);
    }
}
