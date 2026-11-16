package io.aegis.proxy;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * A minimal HTTP/1.1 client over a plain socket, so tests control every byte they send (Host,
 * conflicting framing headers, pipelining) and see every byte that comes back.
 */
final class RawClient implements Closeable {

    /** A parsed response. */
    record Response(int status, List<String[]> headers, byte[] body) {

        String header(String name) {
            return headers.stream().filter(h -> h[0].equalsIgnoreCase(name)).map(h -> h[1]).findFirst().orElse(null);
        }

        String text() {
            return new String(body, StandardCharsets.ISO_8859_1);
        }
    }

    private final Socket socket;
    private final InputStream in;
    private final OutputStream out;

    /** Speaks over an already connected socket, such as a TLS one. */
    RawClient(Socket connected, int readTimeoutMillis) throws IOException {
        socket = connected;
        socket.setSoTimeout(readTimeoutMillis);
        in = socket.getInputStream();
        out = socket.getOutputStream();
    }

    RawClient(int port, int readTimeoutMillis) throws IOException {
        this(plainSocket(port), readTimeoutMillis);
    }

    private static Socket plainSocket(int port) throws IOException {
        Socket plain = new Socket();
        plain.connect(new InetSocketAddress("127.0.0.1", port), 5_000);
        return plain;
    }

    RawClient(int port) throws IOException {
        this(port, 10_000);
    }

    /** Sends a GET with a Host header plus the given {@code Name: value} lines and reads the response. */
    Response get(String path, String... headerLines) throws IOException {
        return send("GET", path, null, headerLines);
    }

    Response send(String method, String path, byte[] body, String... headerLines) throws IOException {
        StringBuilder head = new StringBuilder(method + " " + path + " HTTP/1.1\r\n");
        boolean hasHost = false;
        for (String line : headerLines) {
            hasHost |= line.toLowerCase(Locale.ROOT).startsWith("host:");
            head.append(line).append("\r\n");
        }
        if (!hasHost) {
            head.append("Host: localhost\r\n");
        }
        if (body != null) {
            head.append("Content-Length: ").append(body.length).append("\r\n");
        }
        head.append("\r\n");
        write(head.toString().getBytes(StandardCharsets.ISO_8859_1));
        if (body != null) {
            write(body);
        }
        return readResponse(method.equals("HEAD"));
    }

    void write(byte[] bytes) throws IOException {
        out.write(bytes);
        out.flush();
    }

    void writeText(String text) throws IOException {
        write(text.getBytes(StandardCharsets.ISO_8859_1));
    }

    Response readResponse(boolean headRequest) throws IOException {
        String statusLine = readLine();
        if (statusLine == null) {
            throw new IOException("connection closed before a response");
        }
        int status = Integer.parseInt(statusLine.split(" ")[1]);
        List<String[]> headers = new ArrayList<>();
        for (String line = readLine(); !line.isEmpty(); line = readLine()) {
            int colon = line.indexOf(':');
            headers.add(new String[] {line.substring(0, colon), line.substring(colon + 1).strip()});
        }
        Response shell = new Response(status, headers, new byte[0]);
        byte[] body;
        if (headRequest || status == 204 || status == 304) {
            body = new byte[0];
        } else if ("chunked".equalsIgnoreCase(shell.header("Transfer-Encoding"))) {
            body = readChunked();
        } else if (shell.header("Content-Length") != null) {
            body = in.readNBytes(Integer.parseInt(shell.header("Content-Length")));
        } else {
            body = in.readAllBytes();
        }
        return new Response(status, headers, body);
    }

    /** True when the server has closed its side (the next read returns end of stream). */
    boolean isClosedByServer() throws IOException {
        try {
            return in.read() == -1;
        } catch (java.net.SocketTimeoutException e) {
            return false;
        }
    }

    private byte[] readChunked() throws IOException {
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        while (true) {
            int size = Integer.parseInt(readLine().strip(), 16);
            if (size == 0) {
                while (!readLine().isEmpty()) {
                    // skip trailers
                }
                return body.toByteArray();
            }
            body.write(in.readNBytes(size));
            readLine();
        }
    }

    private String readLine() throws IOException {
        ByteArrayOutputStream line = new ByteArrayOutputStream();
        int previous = -1;
        for (int b = in.read(); b != -1; b = in.read()) {
            if (b == '\n' && previous == '\r') {
                byte[] bytes = line.toByteArray();
                return new String(bytes, 0, bytes.length - 1, StandardCharsets.ISO_8859_1);
            }
            line.write(b);
            previous = b;
        }
        return line.size() == 0 ? null : line.toString(StandardCharsets.ISO_8859_1);
    }

    @Override
    public void close() throws IOException {
        socket.close();
    }
}
