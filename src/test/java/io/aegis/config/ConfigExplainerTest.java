package io.aegis.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class ConfigExplainerTest {

    @Test
    void explainsEveryKnobWithItsSourceAndListsWhatIsLoosened() {
        String yaml = """
                profile: strict
                listener:
                  tls: false
                  port: 8080
                log:
                  rotate_at: 1MB
                firewall:
                  deny: [203.0.113.0/24]
                rule_sets:
                  - name: core
                    file: core.rules
                    mode: block
                  - name: et-open
                    file: et.rules
                    mode: monitor
                waf:
                  block_threshold: 8
                exemptions:
                  - name: scanner
                    sources: [10.20.0.5]
                    skip: [rate_limit, "sid:942100"]
                    reason: Weekly scan
                    owner: sec@example.com
                routes:
                  - name: web
                    backends: [127.0.0.1:9001]
                    waf:
                      on_body_over_limit: pass
                    rule_sets:
                      core: monitor
                    rules:
                      - sid: 7
                        mode: disabled
                        score: 2
                """;
        assertThat(ConfigExplainer.explain(yaml)).isEqualTo("""
                profile = strict   (set in file)
                rule_sets.core.name = core   (set in file)
                rule_sets.core.file = core.rules   (set in file)
                rule_sets.core.mode = block   (set in file)
                rule_sets.et-open.name = et-open   (set in file)
                rule_sets.et-open.file = et.rules   (set in file)
                rule_sets.et-open.mode = monitor   (set in file)
                exemptions.scanner.name = scanner   (set in file)
                exemptions.scanner.sources = [10.20.0.5/32]   (set in file)
                exemptions.scanner.skip = [rate_limit, sid:942100]   (set in file)
                exemptions.scanner.reason = Weekly scan   (set in file)
                exemptions.scanner.owner = sec@example.com   (set in file)
                listener.bind = 0.0.0.0   (built-in default)
                listener.port = 8080   (set in file)
                listener.tls = false   (set in file)
                listener.max_header_bytes = 16KB   (built-in default)
                listener.max_body_bytes = 10MB   (built-in default)
                listener.header_timeout = 10s   (built-in default)
                listener.idle_timeout = 1m   (built-in default)
                listener.drain_timeout = 30s   (built-in default)
                admin.enabled = true   (built-in default)
                admin.bind = 127.0.0.1   (built-in default)
                admin.port = 9090   (built-in default)
                log.directory = logs   (built-in default)
                log.rotate_at = 1MB   (set in file)
                log.keep_files = 10   (built-in default)
                log.logged_query_params = [page, limit, sort]   (built-in default)
                client_ip.trusted_proxies = []   (built-in default)
                firewall.allow = []   (built-in default)
                firewall.deny = [203.0.113.0/24]   (set in file)
                firewall.rate_limit.enabled = true   (built-in default)
                firewall.rate_limit.requests_per_second = 100   (built-in default)
                firewall.rate_limit.burst = 50   (built-in default)
                firewall.rate_limit.ipv4_prefix = 32   (built-in default)
                firewall.rate_limit.ipv6_prefix = 64   (built-in default)
                firewall.rate_limit.max_tracked_clients = 100000   (built-in default)
                routes.web.name = web   (set in file)
                routes.web.host = *   (built-in default)
                routes.web.path_prefix = /   (built-in default)
                routes.web.backends = [127.0.0.1:9001]   (set in file)
                routes.web.health.failures_to_eject = 3   (built-in default)
                routes.web.health.ejection_time = 5s   (built-in default)
                routes.web.health.count_server_errors = false   (built-in default)
                routes.web.connect_timeout = 2s   (built-in default)
                routes.web.response_timeout = 30s   (built-in default)
                routes.web.upstream_tls.enabled = false   (built-in default)
                routes.web.waf.block_threshold = 8   (global waf)
                routes.web.waf.body_scan_limit = 128KB   (profile strict)
                routes.web.waf.on_body_over_limit = pass   (route web)
                routes.web.waf.inspection_budget = 5ms   (profile strict)
                routes.web.waf.on_budget_exceeded = block   (profile strict)
                routes.web.waf.on_engine_error = block   (profile strict)
                routes.web.rule_sets.core = monitor   (route web)
                routes.web.rule_sets.et-open = monitor   (rule_sets declaration)
                routes.web.rules.7.sid = 7   (set in file)
                routes.web.rules.7.mode = disabled   (route web)
                routes.web.rules.7.score = 2   (route web)

                Loosened
                  exemption scanner: clients 10.20.0.5/32 skip rate_limit, sid:942100. Reason: Weekly scan. Owner: sec@example.com.
                  route web runs rule set core in monitor mode
                  route web runs rule set et-open in monitor mode
                  route web runs rule 7 in disabled mode
                """);
    }

    @Test
    void saysWhenNothingIsLoosened() {
        assertThat(ConfigExplainer.explain(TestYaml.MINIMAL)).endsWith("\nLoosened\n  nothing\n");
    }

    @Test
    void doesNotRevealCertificateProviderSettingValues() {
        String yaml = TestYaml.MINIMAL.replace("tls: false", "tls: true") + """
                tls:
                  - hostname: a.example.com
                    certificate:
                      type: vault
                      token: s3cret
                """;
        assertThat(ConfigExplainer.explain(yaml))
                .contains("tls.a.example.com.certificate.settings = [token]")
                .doesNotContain("s3cret");
    }

    @Test
    void refusesToExplainAnInvalidConfiguration() {
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> ConfigExplainer.explain("profile: nope\n"))
                .isInstanceOf(ConfigException.class);
    }
}
