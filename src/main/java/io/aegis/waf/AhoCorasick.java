package io.aegis.waf;

import java.util.Arrays;
import java.util.List;
import java.util.function.IntConsumer;

/**
 * A multi-pattern matcher that finds every pattern in a text with one table lookup per byte.
 *
 * <p>It is a full DFA: the failure links of the classic Aho-Corasick automaton are resolved at
 * build time into the transition table, so scanning never walks back along a link. The table is a
 * flat {@code int[]} indexed {@code state * classCount + byteClass}.
 *
 * <p><b>Byte classes.</b> Patterns use few distinct bytes, so the 256 byte values are mapped to
 * equivalence classes first: bytes that look the same to every pattern share a class, and all
 * bytes that occur in no pattern share class 0. The table has {@code states x classes} entries
 * instead of {@code states x 256}, which is what lets tens of thousands of rules fit in tens of
 * megabytes.
 *
 * <p>Matching is always ASCII case-insensitive (A–Z fold to a–z), so patterns and text share one
 * class per letter. Callers needing exact case confirm candidates afterwards.
 *
 * <p>Texts and patterns hold one byte per char; a char above 0xFF is rejected (patterns) or fails
 * with {@link ArrayIndexOutOfBoundsException} (texts) rather than being misread.
 */
final class AhoCorasick {

    private static final int ROOT = 0;

    private final int[] classOf;
    private final int classCount;
    private final int[] table;
    /** Per state, the ids of all patterns that end there, own and inherited by suffix; null when none. */
    private final int[][] outputs;

    /**
     * @param patterns non-empty strings; the id reported for a pattern is its index in this list.
     *                 Duplicates are allowed and each reports under its own id.
     */
    AhoCorasick(List<String> patterns) {
        classOf = byteClasses(patterns);
        classCount = Arrays.stream(classOf).max().getAsInt() + 1;
        Trie trie = buildTrie(patterns);
        int[] failure = new int[trie.stateCount];
        int[] breadthFirst = completeTransitions(trie, failure);
        table = Arrays.copyOf(trie.table, trie.stateCount * classCount);
        outputs = collectOutputs(trie, failure, breadthFirst);
    }

    /** Calls {@code onPattern} with the id of every pattern occurrence, at the position it ends. */
    void scan(String text, IntConsumer onPattern) {
        int state = ROOT;
        for (int i = 0; i < text.length(); i++) {
            state = table[state * classCount + classOf[text.charAt(i)]];
            int[] ids = outputs[state];
            if (ids != null) {
                for (int id : ids) {
                    onPattern.accept(id);
                }
            }
        }
    }

    /** Memory held by the transition table and the output references, ignoring object headers. */
    long approximateBytes() {
        return 4L * table.length + 8L * outputs.length;
    }

    int stateCount() {
        return outputs.length;
    }

    int classCount() {
        return classCount;
    }

    private static int[] byteClasses(List<String> patterns) {
        boolean[] used = new boolean[256];
        for (String pattern : patterns) {
            if (pattern.isEmpty()) {
                throw new IllegalArgumentException("An empty pattern would match everywhere");
            }
            for (int i = 0; i < pattern.length(); i++) {
                char c = pattern.charAt(i);
                if (c > 0xFF) {
                    throw new IllegalArgumentException("Pattern char U+%04X is not a byte".formatted((int) c));
                }
                used[Ascii.toLower(c)] = true;
            }
        }
        int[] classOfFolded = new int[256];
        int nextClass = 1;
        for (int b = 0; b < 256; b++) {
            if (used[b]) {
                classOfFolded[b] = nextClass++;
            }
        }
        int[] classOf = new int[256];
        for (int b = 0; b < 256; b++) {
            classOf[b] = classOfFolded[Ascii.toLower((char) b)];
        }
        return classOf;
    }

    /**
     * The plain trie of all patterns. State 0 is the root and no edge leads back to it, so a 0 in
     * the table means "no edge yet"; that is why this phase needs no separate marker value.
     */
    private Trie buildTrie(List<String> patterns) {
        int maxStates = 1 + patterns.stream().mapToInt(String::length).sum();
        int[] trieTable = new int[Math.multiplyExact(maxStates, classCount)];
        int[] endState = new int[patterns.size()];
        int stateCount = 1;
        for (int id = 0; id < patterns.size(); id++) {
            int state = ROOT;
            for (char c : patterns.get(id).toCharArray()) {
                int slot = state * classCount + classOf[c];
                if (trieTable[slot] == 0) {
                    trieTable[slot] = stateCount++;
                }
                state = trieTable[slot];
            }
            endState[id] = state;
        }
        return new Trie(trieTable, stateCount, endState);
    }

    /**
     * Fills every missing edge with the edge the failure state would take, shallowest states first
     * so that the failure state's row is already complete when it is copied. Returns the states in
     * that breadth-first order, root excluded.
     */
    private int[] completeTransitions(Trie trie, int[] failure) {
        int[] table = trie.table;
        int[] queue = new int[trie.stateCount - 1];
        int tail = 0;
        for (int c = 0; c < classCount; c++) {
            if (table[c] != 0) {
                queue[tail++] = table[c];
            }
        }
        for (int head = 0; head < tail; head++) {
            int state = queue[head];
            for (int c = 0; c < classCount; c++) {
                int slot = state * classCount + c;
                int viaFailure = table[failure[state] * classCount + c];
                if (table[slot] != 0) {
                    failure[table[slot]] = viaFailure;
                    queue[tail++] = table[slot];
                } else {
                    table[slot] = viaFailure;
                }
            }
        }
        return queue;
    }

    /** Gives each state its own patterns plus those of its failure state, which is shallower and so done. */
    private static int[][] collectOutputs(Trie trie, int[] failure, int[] breadthFirst) {
        int[][] outputs = new int[trie.stateCount][];
        for (int id = 0; id < trie.endState.length; id++) {
            outputs[trie.endState[id]] = append(outputs[trie.endState[id]], id);
        }
        for (int state : breadthFirst) {
            outputs[state] = union(outputs[state], outputs[failure[state]]);
        }
        return outputs;
    }

    private static int[] append(int[] ids, int id) {
        if (ids == null) {
            return new int[] {id};
        }
        int[] longer = Arrays.copyOf(ids, ids.length + 1);
        longer[ids.length] = id;
        return longer;
    }

    private static int[] union(int[] own, int[] inherited) {
        if (inherited == null) {
            return own;
        }
        if (own == null) {
            return inherited;
        }
        int[] both = Arrays.copyOf(own, own.length + inherited.length);
        System.arraycopy(inherited, 0, both, own.length, inherited.length);
        return both;
    }

    private record Trie(int[] table, int stateCount, int[] endState) {
    }
}
