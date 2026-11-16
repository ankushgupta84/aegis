package io.aegis.rules;

/**
 * A Suricata buffer transform: a rule may ask to inspect a changed copy of a buffer. Transforms
 * apply in the order the rule lists them.
 */
public enum Transform {

    /** {@code url_decode}: percent-decode once and turn {@code +} into a space. */
    URL_DECODE("url_decode"),

    /** {@code to_lowercase}: fold ASCII letters to lowercase. */
    TO_LOWERCASE("to_lowercase"),

    /** {@code compress_whitespace}: collapse each run of whitespace into one space. */
    COMPRESS_WHITESPACE("compress_whitespace"),

    /** {@code strip_whitespace}: remove all whitespace. */
    STRIP_WHITESPACE("strip_whitespace");

    private final String keyword;

    Transform(String keyword) {
        this.keyword = keyword;
    }

    /** The keyword as written in a rule. */
    public String keyword() {
        return keyword;
    }
}
