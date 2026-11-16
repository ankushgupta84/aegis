package io.aegis.loadtest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class RequestMixTest {

    private static final int SAMPLE = 200_000;

    private static LoadTestOptions options(long seed) {
        return LoadTestOptions.parse(new String[] {"--url", "http://h", "--seed", Long.toString(seed),
            "--post-share", "0.30", "--attack-share", "0.01", "--new-connection-share", "0.05",
            "--body-min", "1KB", "--body-max", "64KB"});
    }

    private static List<RequestSpec> draw(long seed) {
        RequestMix mix = new RequestMix(options(seed));
        List<RequestSpec> specs = new ArrayList<>();
        for (int i = 0; i < SAMPLE; i++) {
            specs.add(mix.next());
        }
        return specs;
    }

    private static double share(List<RequestSpec> specs, java.util.function.Predicate<RequestSpec> p) {
        return specs.stream().filter(p).count() / (double) specs.size();
    }

    @Test
    void honorsTheConfiguredShares() {
        List<RequestSpec> specs = draw(1);

        assertThat(share(specs, RequestSpec::post)).isCloseTo(0.30, within(0.01));
        assertThat(share(specs, RequestSpec::attack)).isCloseTo(0.01, within(0.003));
        assertThat(share(specs, RequestSpec::newConnection)).isCloseTo(0.05, within(0.005));
    }

    @Test
    void postBodiesStayInRangeAndAverageTheMidpoint() {
        List<RequestSpec> posts = draw(2).stream().filter(RequestSpec::post).toList();

        assertThat(posts).allSatisfy(p -> assertThat(p.bodyBytes()).isBetween(1024, 64 * 1024));
        assertThat(posts.stream().mapToInt(RequestSpec::bodyBytes).average().orElseThrow())
                .isCloseTo((1024 + 64 * 1024) / 2.0, within(500.0));
    }

    @Test
    void getRequestsHaveNoBody() {
        assertThat(draw(3)).filteredOn(s -> !s.post()).allSatisfy(s -> assertThat(s.bodyBytes()).isZero());
    }

    @Test
    void attackRequestsUseTheBuiltInPayloads() {
        assertThat(draw(4)).filteredOn(RequestSpec::attack)
                .allSatisfy(s -> assertThat(RequestMix.ATTACK_URIS).contains(s.uri()));
    }

    @Test
    void sameSeedGivesTheSameSequence() {
        assertThat(draw(5)).isEqualTo(draw(5));
        assertThat(draw(5)).isNotEqualTo(draw(6));
    }
}
