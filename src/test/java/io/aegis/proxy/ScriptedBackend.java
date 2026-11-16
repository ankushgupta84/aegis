package io.aegis.proxy;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * A backend whose behavior a test scripts, built on raw sockets so it can record the exact bytes
 * Aegis sent and misbehave on purpose: close without answering, never answer, or stream a huge body.
 */
final class ScriptedBackend implements AutoCloseable {

    /** One request as received: the head bytes exactly, and the body. */
    record Request(byte[] headBytes, byte[] body) {

        String head() {
            return new String(headBytes, StandardCharsets.ISO_8859_1);
        }

        List<String> headers(String name) {
            List<String> values = new ArrayList<>();
            for (String line : head().split("\r\n")) {
                int colon = line.indexOf(':');
                if (colon > 0 && line.substring(0, colon).equalsIgnoreCase(name)) {
                    values.add(line.substring(colon + 1).strip());
                }
            }
            return values;
        }

        String header(String name) {
            return headers(name).stream().findFirst().orElse(null);
        }
    }

    /** What the backend does with a request. */
    interface Behavior {
        void respond(Request request, Socket socket) throws IOException;
    }

    private final ServerSocket server;
    private final Behavior behavior;
    private final List<Request> requests = new CopyOnWriteArrayList<>();
    private final List<Socket> sockets = new CopyOnWriteArrayList<>();
    private final AtomicInteger connections = new AtomicInteger();
    private final Thread acceptor;

    private ScriptedBackend(Behavior behavior) throws IOException {
        this.server = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        this.behavior = behavior;
        this.acceptor = new Thread(this::acceptLoop, "scripted-backend-accept");
        acceptor.setDaemon(true);
        acceptor.start();
    }

    static ScriptedBackend start(Behavior behavior) throws IOException {
        return new ScriptedBackend(behavior);
    }

    static ScriptedBackend answering(String body) throws IOException {
        return start(answer(200, body));
    }

    int port() {
        return server.getLocalPort();
    }

    List<Request> requests() {
        return requests;
    }

    int connections() {
        return connections.get();
    }

    // ---- behaviors ----------------------------------------------------------------------------------

    static Behavior answer(int status, String body) {
        return (request, socket) -> reply(socket.getOutputStream(), status, List.of(), body.getBytes(StandardCharsets.UTF_8));
    }

    static Behavior answerWith(int status, List<String> extraHeaders, String body) {
        return (request, socket) -> reply(socket.getOutputStream(), status, extraHeaders, body.getBytes(StandardCharsets.UTF_8));
    }

    /** Answers, then closes the connection shortly after, as a backend does when its keep-alive timeout expires. */
    static Behavior answerThenCloseWhenIdle(String body) {
        return (request, socket) -> {
            reply(socket.getOutputStream(), 200, List.of(), body.getBytes(StandardCharsets.UTF_8));
            Thread closer = new Thread(() -> {
                try {
                    Thread.sleep(50);
                    socket.close();
                } catch (IOException | InterruptedException e) {
                    // The test is over or the proxy already hung up; nothing left to close.
                }
            });
            closer.setDaemon(true);
            closer.start();
        };
    }

    /** Reads the whole request, then closes the connection without a word. */
    static Behavior dieAfterReadingRequest() {
        return (request, socket) -> socket.close();
    }

    /** Reads the request and never answers. */
    static Behavior hang() {
        return (request, socket) -> {
            try {
                Thread.sleep(60_000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        };
    }

    /** Answers {@code 200} with a body of {@code size} bytes taken from {@link #pattern}. */
    static Behavior streamBody(int size) {
        return (request, socket) -> {
            OutputStream out = socket.getOutputStream();
            out.write(("HTTP/1.1 200 OK\r\nContent-Length: " + size + "\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
            out.write(pattern(size));
            out.flush();
        };
    }

    static byte[] pattern(int size) {
        byte[] bytes = new byte[size];
        long state = 42;
        for (int i = 0; i < size; i++) {
            state = state * 6364136223846793005L + 1442695040888963407L;
            bytes[i] = (byte) (state >>> 56);
        }
        return bytes;
    }

    private static void reply(OutputStream out, int status, List<String> extraHeaders, byte[] body) throws IOException {
        StringBuilder head = new StringBuilder("HTTP/1.1 " + status + " X\r\nContent-Length: " + body.length + "\r\n");
        extraHeaders.forEach(h -> head.append(h).append("\r\n"));
        out.write(head.append("\r\n").toString().getBytes(StandardCharsets.ISO_8859_1));
        out.write(body);
        out.flush();
    }

    // ---- plumbing ------------------------------------------------------------------------------------

    private void acceptLoop() {
        while (!server.isClosed()) {
            try {
                Socket socket = server.accept();
                sockets.add(socket);
                connections.incrementAndGet();
                Thread worker = new Thread(() -> serve(socket), "scripted-backend-conn");
                worker.setDaemon(true);
                worker.start();
            } catch (IOException e) {
                return; // the server socket was closed
            }
        }
    }

    private void serve(Socket socket) {
        try (socket) {
            InputStream in = socket.getInputStream();
            while (true) {
                Request request = readRequest(in);
                if (request == null) {
                    return;
                }
                requests.add(request);
                behavior.respond(request, socket);
                if (socket.isClosed()) {
                    return;
                }
            }
        } catch (IOException e) {
            // The proxy hung up or the test closed the backend; either ends this connection.
        }
    }

    private static Request readRequest(InputStream in) throws IOException {
        ByteArrayOutputStream head = new ByteArrayOutputStream();
        int matched = 0;
        while (matched < 4) {
            int b = in.read();
            if (b == -1) {
                return null;
            }
            head.write(b);
            matched = b == (matched % 2 == 0 ? '\r' : '\n') ? matched + 1 : (b == '\r' ? 1 : 0);
        }
        byte[] headBytes = head.toByteArray();
        String text = new String(headBytes, StandardCharsets.ISO_8859_1);
        int length = 0;
        for (String line : text.split("\r\n")) {
            if (line.toLowerCase(Locale.ROOT).startsWith("content-length:")) {
                length = Integer.parseInt(line.substring(15).strip());
            }
        }
        return new Request(headBytes, in.readNBytes(length));
    }

    @Override
    public void close() throws IOException {
        server.close();
        for (Socket socket : sockets) {
            socket.close();
        }
    }
}
