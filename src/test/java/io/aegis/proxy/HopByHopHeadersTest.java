package io.aegis.proxy;

import static org.assertj.core.api.Assertions.assertThat;

import io.netty.handler.codec.http.DefaultHttpHeaders;
import io.netty.handler.codec.http.HttpHeaders;
import org.junit.jupiter.api.Test;

class HopByHopHeadersTest {

    @Test
    void removesTheStandardConnectionScopedHeaders() {
        HttpHeaders headers = new DefaultHttpHeaders()
                .add("Connection", "keep-alive").add("Keep-Alive", "timeout=5").add("Proxy-Authenticate", "Basic")
                .add("Proxy-Authorization", "Basic x").add("TE", "trailers").add("Trailer", "Expires")
                .add("Transfer-Encoding", "chunked").add("Upgrade", "websocket").add("Accept", "*/*");

        HopByHopHeaders.strip(headers);

        assertThat(headers.names()).containsExactly("Accept");
    }

    @Test
    void removesEveryHeaderTheConnectionHeaderNames() {
        HttpHeaders headers = new DefaultHttpHeaders()
                .add("Connection", "X-One").add("connection", "x-two , X-Three").add("X-One", "1")
                .add("X-Two", "2").add("X-Three", "3").add("X-Four", "4");

        HopByHopHeaders.strip(headers);

        assertThat(headers.names()).containsExactly("X-Four");
    }

    @Test
    void connectionCannotNameHostOrContentLengthIntoDisappearing() {
        HttpHeaders headers = new DefaultHttpHeaders()
                .add("Connection", "Host, Content-Length").add("Host", "example.com").add("Content-Length", "4");

        HopByHopHeaders.strip(headers);

        assertThat(headers.get("Host")).isEqualTo("example.com");
        assertThat(headers.get("Content-Length")).isEqualTo("4");
        assertThat(headers.contains("Connection")).isFalse();
    }
}
