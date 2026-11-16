package io.aegis.config;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * One YAML mapping being read. It knows where it sits in the file, so every error names the exact
 * location, and which keys the code asked for, so every other key is reported as unknown.
 *
 * <p>Reading a value never throws: a bad value becomes a problem and reads as absent. The caller
 * checks {@link Problems#count()} before building anything from what it read.
 */
final class Section {
    private final JsonNode node;
    private final String where;
    private final String label;
    private final Problems problems;
    private final Ledger ledger;
    private final Set<String> readKeys = new HashSet<>();
    private final List<Section> children = new ArrayList<>();

    private Section(JsonNode value, String where, String label, Problems problems, Ledger ledger) {
        this.where = where;
        this.label = label;
        this.problems = problems;
        this.ledger = ledger;
        if (value.isObject()) {
            this.node = value;
        } else {
            this.node = JsonNodeFactory.instance.objectNode();
            problems.add(describe(where) + " must be a mapping of settings, but found " + shown(value) + ".");
        }
    }

    static Section root(JsonNode value, Problems problems, Ledger ledger) {
        return new Section(value, "", "", problems, ledger);
    }

    /** Reads {@code key} if present and records it; for settings with no default. */
    <T> Optional<T> optional(String key, ValueType<T> type) {
        Optional<T> given = quiet(key, type);
        given.ifPresent(value -> ledger.record(labelOf(key), type.show(value), Ledger.SET_IN_FILE));
        return given;
    }

    /** Reads {@code key} if present but leaves the ledger to the caller, for values merged across scopes. */
    <T> Optional<T> quiet(String key, ValueType<T> type) {
        readKeys.add(key);
        JsonNode value = node.get(key);
        if (value == null) {
            return Optional.empty();
        }
        try {
            return Optional.of(type.parse(value));
        } catch (IllegalArgumentException e) {
            problems.add(whereOf(key) + ": " + e.getMessage());
            return Optional.empty();
        }
    }

    /** Reads {@code key}, or takes {@code fallback} when it is absent, and records which in the ledger. */
    <T> T value(String key, ValueType<T> type, T fallback) {
        Optional<T> given = quiet(key, type);
        T value = given.orElse(fallback);
        ledger.record(labelOf(key), type.show(value), given.isPresent() ? Ledger.SET_IN_FILE : Ledger.BUILT_IN_DEFAULT);
        return value;
    }

    /** Reads {@code key}, which must be present. */
    <T> Optional<T> required(String key, ValueType<T> type) {
        return required(key, type, "");
    }

    /** Reads {@code key}, which must be present; {@code advice} is added to the error when it is not. */
    <T> Optional<T> required(String key, ValueType<T> type, String advice) {
        Optional<T> given = quiet(key, type);
        if (node.get(key) == null) {
            problems.add((whereOf(key) + " is required but missing. " + advice).strip());
        }
        given.ifPresent(value -> ledger.record(labelOf(key), type.show(value), Ledger.SET_IN_FILE));
        return given;
    }

    /** Reads a list of {@code element}, or takes {@code fallback} when absent. */
    <T> List<T> list(String key, ValueType<T> element, List<T> fallback) {
        Optional<List<T>> given = elements(key, element);
        List<T> value = given.orElse(fallback);
        ledger.record(labelOf(key), showList(value, element),
                given.isPresent() ? Ledger.SET_IN_FILE : Ledger.BUILT_IN_DEFAULT);
        return value;
    }

    /** Reads a list that must be present and hold at least one element. */
    <T> Optional<List<T>> requiredList(String key, ValueType<T> element) {
        Optional<List<T>> given = elements(key, element);
        if (node.get(key) == null) {
            problems.add(whereOf(key) + " is required but missing.");
        } else if (given.isPresent() && given.get().isEmpty()) {
            problems.add(whereOf(key) + " needs at least one entry.");
            return Optional.empty();
        }
        given.ifPresent(value -> ledger.record(labelOf(key), showList(value, element), Ledger.SET_IN_FILE));
        return given;
    }

    /** Reads a mapping from free-form names to {@code valueType}, e.g. rule set name to mode. */
    <T> Map<String, T> map(String key, ValueType<T> valueType) {
        readKeys.add(key);
        Map<String, T> result = new LinkedHashMap<>();
        JsonNode value = node.get(key);
        if (value == null) {
            return result;
        }
        if (!value.isObject()) {
            problems.add(whereOf(key) + " must be a mapping, but found " + shown(value) + ".");
            return result;
        }
        value.properties().forEach(entry -> {
            try {
                result.put(entry.getKey(), valueType.parse(entry.getValue()));
            } catch (IllegalArgumentException e) {
                problems.add(whereOf(key) + "." + entry.getKey() + ": " + e.getMessage());
            }
        });
        return result;
    }

    /** The nested mapping at {@code key}; an empty one when absent. */
    Section child(String key) {
        readKeys.add(key);
        JsonNode value = node.get(key);
        Section child = new Section(value == null ? JsonNodeFactory.instance.objectNode() : value,
                whereOf(key), labelOf(key), problems, ledger);
        children.add(child);
        return child;
    }

    /**
     * The mappings in the list at {@code key}. Each is labelled by its {@code nameKey} value when
     * it has one, e.g. {@code routes.default}, and names must be unique.
     */
    List<Section> children(String key, String nameKey) {
        readKeys.add(key);
        JsonNode value = node.get(key);
        List<Section> result = new ArrayList<>();
        if (value == null) {
            return result;
        }
        if (!value.isArray()) {
            problems.add(whereOf(key) + " must be a list, but found " + shown(value) + ".");
            return result;
        }
        Map<String, Integer> firstUse = new LinkedHashMap<>();
        for (int i = 0; i < value.size(); i++) {
            JsonNode entry = value.get(i);
            String name = entry.path(nameKey).isValueNode() ? entry.get(nameKey).asText() : null;
            String entryWhere = whereOf(key) + "[" + i + "]";
            if (name != null && firstUse.putIfAbsent(name, i) != null) {
                problems.add(entryWhere + "." + nameKey + " '" + name + "' is already used by "
                        + whereOf(key) + "[" + firstUse.get(name) + "]. Each entry needs its own " + nameKey + ".");
            }
            Section section = new Section(entry, entryWhere,
                    name == null ? entryWhere : labelOf(key) + "." + name, problems, ledger);
            children.add(section);
            result.add(section);
        }
        return result;
    }

    /** Takes every key not yet read as a text setting, for plugin-defined settings. */
    Map<String, String> remainingText() {
        Map<String, String> settings = new LinkedHashMap<>();
        node.properties().forEach(entry -> {
            if (readKeys.add(entry.getKey())) {
                if (entry.getValue().isValueNode()) {
                    settings.put(entry.getKey(), entry.getValue().asText());
                } else {
                    problems.add(whereOf(entry.getKey()) + " must be a single value, but found "
                            + shown(entry.getValue()) + ".");
                }
            }
        });
        return settings;
    }

    /** Where this section sits in the knob paths shown to operators, e.g. {@code routes.default}. */
    String label() {
        return label;
    }

    /** Where the knob {@code key} sits in the file, e.g. {@code routes[0].health}. */
    String whereOf(String key) {
        return where.isEmpty() ? key : where + "." + key;
    }

    /** Reports every key nobody asked for, in this section and the ones nested in it. */
    void rejectUnknownKeys() {
        node.fieldNames().forEachRemaining(key -> {
            if (!readKeys.contains(key)) {
                problems.add(unknownKey(key));
            }
        });
        children.forEach(Section::rejectUnknownKeys);
    }

    private String unknownKey(String key) {
        String place = where.isEmpty() ? "at the top level" : "under " + where;
        String advice = Suggestions.closest(key, readKeys)
                .map(close -> "Did you mean '" + close + "'?")
                .orElse("Valid keys here: " + String.join(", ", readKeys.stream().sorted().toList()) + ".");
        return "Unknown key '" + key + "' " + place + ". " + advice;
    }

    private <T> Optional<List<T>> elements(String key, ValueType<T> element) {
        readKeys.add(key);
        JsonNode value = node.get(key);
        if (value == null) {
            return Optional.empty();
        }
        if (!value.isArray()) {
            problems.add(whereOf(key) + " must be a list, e.g. [a, b], but found " + shown(value) + ".");
            return Optional.empty();
        }
        int before = problems.count();
        List<T> parsed = new ArrayList<>();
        for (int i = 0; i < value.size(); i++) {
            try {
                parsed.add(element.parse(value.get(i)));
            } catch (IllegalArgumentException e) {
                problems.add(whereOf(key) + "[" + i + "]: " + e.getMessage());
            }
        }
        return problems.count() > before ? Optional.empty() : Optional.of(parsed);
    }

    private String labelOf(String key) {
        return label.isEmpty() ? key : label + "." + key;
    }

    private static <T> String showList(List<T> values, ValueType<T> element) {
        return values.stream().map(element::show).toList().toString();
    }

    private static String describe(String where) {
        return where.isEmpty() ? "The top level of the file" : where;
    }

    private static String shown(JsonNode value) {
        return "'" + (value.isTextual() ? value.asText() : value.toString()) + "'";
    }
}
