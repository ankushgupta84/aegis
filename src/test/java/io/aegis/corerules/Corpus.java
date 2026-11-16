package io.aegis.corerules;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/** Reads a tab-separated corpus from the test resources; columns are found by their header names. */
final class Corpus {

    private Corpus() {
    }

    static List<CorpusRequest> read(String resource) {
        List<String> lines = lines("/corerules/" + resource);
        List<String> columns = Arrays.asList(lines.get(0).split("\t", -1));
        List<CorpusRequest> requests = new ArrayList<>();
        for (String line : lines.subList(1, lines.size())) {
            if (line.isBlank() || line.startsWith("#")) {
                continue;
            }
            String[] fields = line.split("\t", -1);
            if (fields.length != columns.size()) {
                throw new IllegalStateException(resource + ": expected " + columns.size() + " fields but found "
                        + fields.length + " in line: " + line);
            }
            requests.add(new CorpusRequest(field(columns, fields, "id"), field(columns, fields, "kind"),
                    field(columns, fields, "class"), field(columns, fields, "method"),
                    field(columns, fields, "target"), field(columns, fields, "user_agent"),
                    field(columns, fields, "content_type"), field(columns, fields, "headers"),
                    field(columns, fields, "body"), field(columns, fields, "note"), field(columns, fields, "reason")));
        }
        return requests;
    }

    /** The named field, or the empty string when the file has no such column. */
    private static String field(List<String> columns, String[] fields, String name) {
        int index = columns.indexOf(name);
        return index < 0 ? "" : fields[index];
    }

    private static List<String> lines(String resource) {
        try (var in = Corpus.class.getResourceAsStream(resource)) {
            if (in == null) {
                throw new IllegalStateException("Missing test resource " + resource);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8).lines().toList();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
