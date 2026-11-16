package io.aegis.tls;

import io.aegis.plugin.CertificateProvider;
import io.aegis.plugin.CertificateUnavailableException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

/**
 * Serves a certificate chain and key from PEM files and notices when they change, which covers
 * an internal CA that renews by rewriting files.
 *
 * <p>Change is detected by content hash, not modification time, so a copy that preserves the
 * time still counts. Files caught mid-write, or a certificate replaced before its key, fail to
 * load: that is reported once and the previous material stays in use until the files are
 * consistent again.
 *
 * <p>The listener and failure callback run on the polling thread and must not throw.
 */
public final class FileWatchCertificateProvider implements CertificateProvider {

    private final Path certFile;
    private final Path keyFile;
    private final Duration pollInterval;

    private ScheduledExecutorService poller;
    private Consumer<Material> listener;
    private Consumer<CertificateUnavailableException> onFailure;
    /** Digest of the files last delivered to the caller; null before the first load. */
    private String deliveredDigest;
    /** What the last reported failure looked like, so the same bad state is reported once. */
    private String reportedFailure;

    public FileWatchCertificateProvider(Path certFile, Path keyFile, Duration pollInterval) {
        this.certFile = certFile;
        this.keyFile = keyFile;
        this.pollInterval = pollInterval;
    }

    @Override
    public synchronized Material load() {
        var files = readFiles();
        var material = PemMaterial.parse(certFile, files.cert(), keyFile, files.key());
        deliveredDigest = files.digest();
        return material;
    }

    /** Starts polling every poll interval; call after {@link #load()} so its files are the baseline. */
    @Override
    public synchronized void watch(Consumer<Material> listener, Consumer<CertificateUnavailableException> onFailure) {
        if (poller != null) {
            throw new IllegalStateException("already watching " + certFile);
        }
        this.listener = listener;
        this.onFailure = onFailure;
        poller = Executors.newSingleThreadScheduledExecutor(runnable -> {
            var thread = new Thread(runnable, "certificate-watch-" + certFile.getFileName());
            thread.setDaemon(true);
            return thread;
        });
        poller.scheduleWithFixedDelay(this::pollOnce, pollInterval.toMillis(), pollInterval.toMillis(),
                TimeUnit.MILLISECONDS);
    }

    /** Checks the files once; the scheduler calls this every poll interval, and tests call it directly. */
    synchronized void pollOnce() {
        FileContents files;
        try {
            files = readFiles();
        } catch (CertificateUnavailableException e) {
            reportFailure(e.getMessage(), e);
            return;
        }
        if (files.digest().equals(deliveredDigest)) {
            reportedFailure = null;
            return;
        }
        if (files.digest().equals(reportedFailure)) {
            return;
        }
        try {
            var material = PemMaterial.parse(certFile, files.cert(), keyFile, files.key());
            deliveredDigest = files.digest();
            reportedFailure = null;
            listener.accept(material);
        } catch (CertificateUnavailableException e) {
            reportFailure(files.digest(), e);
        }
    }

    private void reportFailure(String failureKey, CertificateUnavailableException failure) {
        if (!failureKey.equals(reportedFailure)) {
            reportedFailure = failureKey;
            onFailure.accept(failure);
        }
    }

    private FileContents readFiles() {
        var cert = readFile("cert_file", certFile);
        var key = readFile("key_file", keyFile);
        return new FileContents(cert, key, sha256Hex(cert) + ":" + sha256Hex(key));
    }

    private static byte[] readFile(String setting, Path file) {
        try {
            return Files.readAllBytes(file);
        } catch (IOException e) {
            throw new CertificateUnavailableException(
                    setting + " " + file + " cannot be read: " + e.getMessage(), e);
        }
    }

    private static String sha256Hex(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("every JVM provides SHA-256", e);
        }
    }

    private record FileContents(byte[] cert, byte[] key, String digest) {
    }

    @Override
    public synchronized void close() {
        if (poller != null) {
            poller.shutdownNow();
        }
    }
}
