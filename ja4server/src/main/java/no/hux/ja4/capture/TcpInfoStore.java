package no.hux.ja4.capture;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Short-lived store correlating captured TCP handshake data to Netty
 * connections by the client {@code ip:port} key.
 *
 * <p>Entries are written by the capture thread when a SYN is seen and consumed
 * by the request handler on the first HTTP request. They are evicted after a
 * short TTL (a handshake-to-request window is sub-second in practice) and the
 * map is size-capped so handshake floods from scanners cannot exhaust memory.
 */
public final class TcpInfoStore {

  public static final int DEFAULT_MAX_ENTRIES = 100_000;
  public static final long DEFAULT_TTL_SECONDS = 10L;

  private final Map<String, TcpHandshakeInfo> store;
  private final long ttlNanos;
  private final int maxEntries;
  private final Logger logger;
  private final ScheduledExecutorService scheduler;

  public TcpInfoStore(Logger logger) {
    this(DEFAULT_TTL_SECONDS, DEFAULT_MAX_ENTRIES, logger);
  }

  public TcpInfoStore(long ttlSeconds, int maxEntries, Logger logger) {
    if (maxEntries < 1) {
      throw new IllegalArgumentException("maxEntries must be >= 1");
    }
    this.ttlNanos = TimeUnit.SECONDS.toNanos(Math.max(1L, ttlSeconds));
    this.maxEntries = maxEntries;
    this.logger = logger;
    this.store = new LinkedHashMap<>(16, 0.75f, false) {
      @Override
      protected boolean removeEldestEntry(Map.Entry<String, TcpHandshakeInfo> eldest) {
        return size() > TcpInfoStore.this.maxEntries;
      }
    };
    this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
      Thread thread = new Thread(r, "ja4-capture-cleanup");
      thread.setDaemon(true);
      return thread;
    });
    long intervalSeconds = Math.max(1L, ttlSeconds);
    scheduler.scheduleAtFixedRate(this::cleanup, intervalSeconds, intervalSeconds,
        TimeUnit.SECONDS);
  }

  public static String key(String ip, int port) {
    return ip + ":" + port;
  }

  /**
   * Returns the handshake info for {@code ip:port}, creating an empty entry when
   * absent. Used by the capture thread to accumulate handshake observations.
   */
  public TcpHandshakeInfo getOrCreate(String ip, int port) {
    String k = key(ip, port);
    synchronized (store) {
      // Re-insert to move the entry to the tail (newest) so it survives
      // eldest-entry eviction while the handshake is in progress.
      TcpHandshakeInfo existing = store.remove(k);
      if (existing == null) {
        existing = new TcpHandshakeInfo(System.nanoTime());
      }
      store.put(k, existing);
      return existing;
    }
  }

  /** Returns the handshake info for {@code ip:port}, or {@code null} if absent. */
  public TcpHandshakeInfo get(String ip, int port) {
    synchronized (store) {
      return store.get(key(ip, port));
    }
  }

  public int size() {
    synchronized (store) {
      return store.size();
    }
  }

  public void shutdown() {
    scheduler.shutdownNow();
  }

  private void cleanup() {
    try {
      long cutoff = System.nanoTime() - ttlNanos;
      synchronized (store) {
        store.entrySet().removeIf(e -> e.getValue().getCreatedNanos() < cutoff);
      }
    } catch (Exception ex) {
      logger.log(Level.WARNING, "Failed to clean up TCP handshake store", ex);
    }
  }
}
