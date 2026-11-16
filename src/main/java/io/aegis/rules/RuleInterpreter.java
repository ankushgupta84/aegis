package io.aegis.rules;

import io.aegis.http.RuleBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

/**
 * Reads the options of one rule in order and decides its {@link RuleStatus}.
 *
 * <p>Only keywords named here are supported; every other keyword makes the rule unsupported, so a
 * keyword added to Suricata later can never be silently ignored. The interpreter keeps reading
 * after the first problem because the status order puts "not applicable" ahead of "unsupported":
 * a DNS rule that uses an unknown keyword is still not applicable. The first problem found is the
 * one reported.
 */
final class RuleInterpreter {

    private static final Map<String, RuleBuffer> STICKY_BUFFERS = indexBuffers(RuleBuffer::stickyKeyword);
    private static final Map<String, RuleBuffer> LEGACY_MODIFIERS = indexBuffers(RuleBuffer::legacyModifier);
    private static final Map<String, Transform> TRANSFORMS = new HashMap<>();
    private static final Set<String> RESPONSE_BUFFERS = Set.of("http.stat_code", "http.stat_msg",
            "http.response_body", "http.response_line", "http.server", "http.location", "file.data", "file_data");
    private static final Set<String> RESPONSE_MODIFIERS = Set.of("http_stat_code", "http_stat_msg", "http_server_body");
    private static final Set<String> HARMLESS_FLOW = Set.of("to_server", "from_client", "established", "stateless",
            "only_stream", "no_stream");
    private static final Set<String> RESPONSE_FLOW = Set.of("to_client", "from_server");
    private static final Set<String> INSPECTED_PROTOCOLS = Set.of("http", "tcp");

    static {
        Arrays.stream(Transform.values()).forEach(t -> TRANSFORMS.put(t.keyword(), t));
    }

    private final RuleHeader header;
    private final List<RuleOption> options;
    private final String raw;
    private final RuleMetadata metadata = new RuleMetadata();
    private final List<Condition> conditions = new ArrayList<>();
    private final List<Transform> transforms = new ArrayList<>();
    private RuleBuffer stickyBuffer;
    private boolean stickyBufferUnknown;
    private ContentDraft pendingContent;
    private boolean readsRawPayload;
    private Rejection firstRejection;

    private RuleInterpreter(RuleHeader header, List<RuleOption> options, String raw) {
        this.header = header;
        this.options = options;
        this.raw = raw;
    }

    static ClassifiedRule classify(RuleHeader header, List<RuleOption> options, String raw) {
        return new RuleInterpreter(header, options, raw).classify();
    }

    private ClassifiedRule classify() {
        for (RuleOption option : options) {
            try {
                apply(option);
            } catch (Rejection rejection) {
                firstRejection = firstRejection == null ? rejection : firstRejection;
            }
        }
        flushContent();
        if (metadata.sid() == 0) {
            return skipped(RuleStatus.UNSUPPORTED, firstRejection != null ? firstRejection.getMessage()
                    : Rejection.syntax("rule has no sid").getMessage());
        }
        if (!INSPECTED_PROTOCOLS.contains(header.protocol())) {
            return skipped(RuleStatus.NOT_APPLICABLE,
                    "protocol '" + header.protocol() + "' carries traffic Aegis never sees");
        }
        if (readsRawPayload) {
            return skipped(RuleStatus.NOT_APPLICABLE, "matches raw TCP payload; Aegis inspects decoded HTTP");
        }
        if (firstRejection != null) {
            return skipped(RuleStatus.UNSUPPORTED, firstRejection.getMessage());
        }
        if (conditions.isEmpty()) {
            return skipped(RuleStatus.UNSUPPORTED, "no inspectable condition: the rule has no content or pcre");
        }
        return activeRule();
    }

    private ClassifiedRule activeRule() {
        try {
            int score = ScoreTable.defaultScore(metadata.classtype(), metadata.priority(), metadata.metadata());
            return ClassifiedRule.active(new SuricataRule(metadata.sid(), metadata.rev(), header.action(),
                    metadata.msg(), metadata.classtype(), score, metadata.metadata(), metadata.references(),
                    conditions, raw));
        } catch (Rejection rejection) {
            return skipped(RuleStatus.UNSUPPORTED, rejection.getMessage());
        }
    }

    private ClassifiedRule skipped(RuleStatus status, String reason) {
        return ClassifiedRule.skipped(metadata.sid(), metadata.rev(), status, reason, raw);
    }

    private void apply(RuleOption option) {
        if (metadata.accept(option)) {
            return;
        }
        switch (option.name()) {
            case "content" -> startContent(option);
            case "pcre" -> addPcre(option);
            case "nocase" -> contentFor(option).nocase();
            case "startswith" -> contentFor(option).startsWith();
            case "endswith" -> contentFor(option).endsWith();
            case "fast_pattern" -> contentFor(option).fastPattern();
            case "offset" -> contentFor(option).offset(number(option));
            case "depth" -> contentFor(option).depth(number(option));
            case "distance" -> contentFor(option).distance(number(option));
            case "within" -> contentFor(option).within(number(option));
            case "flow" -> checkFlow(option);
            default -> applyBufferKeyword(option);
        }
    }

    private void applyBufferKeyword(RuleOption option) {
        String name = option.name();
        if (STICKY_BUFFERS.containsKey(name)) {
            flushContent();
            stickyBuffer = STICKY_BUFFERS.get(name);
            stickyBufferUnknown = false;
            transforms.clear();
        } else if (LEGACY_MODIFIERS.containsKey(name)) {
            contentFor(option).useBuffer(LEGACY_MODIFIERS.get(name));
        } else if (TRANSFORMS.containsKey(name)) {
            addTransform(TRANSFORMS.get(name));
        } else if (RESPONSE_MODIFIERS.contains(name)) {
            if (pendingContent != null) {
                pendingContent.markBufferUnknown();
            }
            throw Rejection.response("keyword '" + name + "'");
        } else if (RESPONSE_BUFFERS.contains(name)) {
            startUnknownBuffer();
            throw Rejection.response("keyword '" + name + "'");
        } else {
            // A keyword without a value may be a sticky buffer we do not know; what follows it is not raw payload.
            if (!option.hasValue()) {
                startUnknownBuffer();
            }
            throw Rejection.keyword(name);
        }
    }

    private void startUnknownBuffer() {
        flushContent();
        stickyBuffer = null;
        stickyBufferUnknown = true;
    }

    private void addTransform(Transform transform) {
        flushContent();
        if (stickyBuffer == null && !stickyBufferUnknown) {
            throw Rejection.syntax("'" + transform.keyword() + "' needs a buffer before it");
        }
        transforms.add(transform);
    }

    private void startContent(RuleOption option) {
        flushContent();
        QuotedValue value = QuotedValue.parse(option.requireValue());
        pendingContent = new ContentDraft(ContentDecoder.decode(value.body()), value.negated());
    }

    private void addPcre(RuleOption option) {
        flushContent();
        ParsedPcre pcre = PcreTranslator.parse(option.requireValue());
        boolean flagged = pcre.bufferFlag() != null;
        RuleBuffer buffer = flagged ? pcre.bufferFlag() : stickyBuffer;
        if (buffer != null) {
            conditions.add(pcre.on(buffer, flagged ? List.of() : List.copyOf(transforms)));
        } else if (!stickyBufferUnknown) {
            readsRawPayload = true;
        }
    }

    /** Closes the content being built: no modifier can follow once another condition or buffer starts. */
    private void flushContent() {
        if (pendingContent == null) {
            return;
        }
        ContentDraft draft = pendingContent;
        pendingContent = null;
        boolean legacy = draft.legacyBuffer() != null;
        RuleBuffer buffer = legacy ? draft.legacyBuffer() : stickyBuffer;
        if (buffer != null) {
            conditions.add(draft.on(buffer, legacy ? List.of() : List.copyOf(transforms)));
        } else if (!draft.bufferUnknown() && !stickyBufferUnknown) {
            readsRawPayload = true;
        }
    }

    private ContentDraft contentFor(RuleOption option) {
        if (pendingContent == null) {
            throw Rejection.syntax("'" + option.name() + "' must directly follow a content");
        }
        return pendingContent;
    }

    private static int number(RuleOption option) {
        String text = option.requireValue();
        try {
            return Integer.parseInt(text);
        } catch (NumberFormatException notANumber) {
            throw Rejection.because("'" + option.name() + "' value '" + text
                    + "' is not a number; byte_extract variables are not supported");
        }
    }

    private static void checkFlow(RuleOption option) {
        for (String setting : option.requireValue().split(",")) {
            String name = setting.strip();
            if (RESPONSE_FLOW.contains(name)) {
                throw Rejection.response("flow '" + name + "'");
            }
            if (!HARMLESS_FLOW.contains(name)) {
                throw Rejection.because("flow setting '" + name + "' is not supported");
            }
        }
    }

    private static Map<String, RuleBuffer> indexBuffers(Function<RuleBuffer, String> keyword) {
        Map<String, RuleBuffer> index = new HashMap<>();
        for (RuleBuffer buffer : RuleBuffer.values()) {
            if (keyword.apply(buffer) != null) {
                index.put(keyword.apply(buffer), buffer);
            }
        }
        return index;
    }
}
