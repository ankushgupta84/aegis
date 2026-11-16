package io.aegis.observe;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * The append-only log file and its numbered predecessors ({@code aegis.log.1} is the newest).
 * Not thread-safe: the single writer thread owns it.
 *
 * <p>The stream is opened lazily, so a rotation that fails halfway leaves the file closed and
 * the next append simply reopens {@code aegis.log} instead of wedging the log.
 */
final class RotatingFile implements AutoCloseable {

    static final String NAME = "aegis.log";

    private final Path active;
    private final long rotateAtBytes;
    private final int keepFiles;
    private OutputStream out;
    private long size;

    RotatingFile(Path directory, long rotateAtBytes, int keepFiles) throws IOException {
        Files.createDirectories(directory);
        this.active = directory.resolve(NAME);
        this.rotateAtBytes = rotateAtBytes;
        this.keepFiles = keepFiles;
    }

    void appendLine(String line) throws IOException {
        byte[] bytes = (line + "\n").getBytes(StandardCharsets.UTF_8);
        open();
        out.write(bytes);
        size += bytes.length;
        if (size >= rotateAtBytes) {
            rotate();
        }
    }

    void flush() throws IOException {
        if (out != null) {
            out.flush();
        }
    }

    @Override
    public void close() throws IOException {
        closeStream();
    }

    private void open() throws IOException {
        if (out == null) {
            size = Files.exists(active) ? Files.size(active) : 0;
            out = new BufferedOutputStream(Files.newOutputStream(active, StandardOpenOption.CREATE, StandardOpenOption.APPEND));
        }
    }

    private void closeStream() throws IOException {
        OutputStream stream = out;
        out = null;
        if (stream != null) {
            stream.close();
        }
    }

    private void rotate() throws IOException {
        closeStream();
        if (keepFiles == 0) {
            Files.delete(active);
            return;
        }
        Files.deleteIfExists(numbered(keepFiles));
        for (int i = keepFiles - 1; i >= 1; i--) {
            if (Files.exists(numbered(i))) {
                Files.move(numbered(i), numbered(i + 1));
            }
        }
        Files.move(active, numbered(1));
    }

    private Path numbered(int index) {
        return active.resolveSibling(NAME + "." + index);
    }
}
