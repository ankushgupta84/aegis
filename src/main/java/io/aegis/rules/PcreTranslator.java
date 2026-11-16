package io.aegis.rules;

import com.google.re2j.Pattern;
import com.google.re2j.PatternSyntaxException;
import io.aegis.http.RuleBuffer;
import java.util.Map;

/**
 * Reads {@code pcre:"/regex/flags"} and proves the expression runs on RE2/J.
 *
 * <p>Why RE2/J: it matches in linear time, so no rule can be turned into a ReDoS. The price is
 * that lookarounds, backreferences and possessive quantifiers are refused, and the whole rule is
 * classified unsupported.
 */
final class PcreTranslator {

    private static final Map<Character, RuleBuffer> BUFFER_FLAGS = Map.of(
            'U', RuleBuffer.HTTP_URI,
            'I', RuleBuffer.HTTP_URI_RAW,
            'H', RuleBuffer.HTTP_HEADER,
            'P', RuleBuffer.HTTP_REQUEST_BODY,
            'C', RuleBuffer.HTTP_COOKIE,
            'M', RuleBuffer.HTTP_METHOD,
            'V', RuleBuffer.HTTP_USER_AGENT,
            'W', RuleBuffer.HTTP_HOST);

    private PcreTranslator() {
    }

    static ParsedPcre parse(String value) {
        QuotedValue quoted = QuotedValue.parse(value);
        String body = quoted.body();
        int closing = body.lastIndexOf('/');
        if (!body.startsWith("/") || closing == 0) {
            throw Rejection.syntax("pcre must look like \"/regex/flags\"");
        }
        String regex = body.substring(1, closing);
        boolean ignoreCase = false;
        boolean dotAll = false;
        boolean multiline = false;
        boolean relative = false;
        RuleBuffer bufferFlag = null;
        for (char flag : body.substring(closing + 1).toCharArray()) {
            switch (flag) {
                case 'i' -> ignoreCase = true;
                case 's' -> dotAll = true;
                case 'm' -> multiline = true;
                case 'R' -> relative = true;
                default -> {
                    RuleBuffer named = BUFFER_FLAGS.get(flag);
                    if (named == null) {
                        throw Rejection.because("pcre flag '" + flag + "' is not supported");
                    }
                    if (bufferFlag != null) {
                        throw Rejection.syntax("pcre names two buffers");
                    }
                    bufferFlag = named;
                }
            }
        }
        requireLinearTime(regex, ignoreCase, dotAll, multiline);
        return new ParsedPcre(regex, quoted.negated(), ignoreCase, dotAll, multiline, relative, bufferFlag);
    }

    private static void requireLinearTime(String regex, boolean ignoreCase, boolean dotAll, boolean multiline) {
        int flags = (ignoreCase ? Pattern.CASE_INSENSITIVE : 0)
                | (dotAll ? Pattern.DOTALL : 0)
                | (multiline ? Pattern.MULTILINE : 0);
        try {
            Pattern.compile(regex, flags);
        } catch (PatternSyntaxException e) {
            throw Rejection.because(
                    "pcre needs a feature a linear-time engine cannot provide: " + e.getDescription() + " in " + e.getPattern());
        }
    }
}
