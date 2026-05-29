package no.hux.ja4.store;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class FingerprintStore {

  public static final int DEFAULT_MAX_ENTRIES = 100_000;

  private final Map<String, FingerprintRecord> store;
  private final Duration ttl;
  private final int maxEntries;
  private final Logger logger;
  private final ScheduledExecutorService scheduler;

  public FingerprintStore(Duration ttl, Logger logger) {
    this(ttl, DEFAULT_MAX_ENTRIES, logger);
  }

  public FingerprintStore(Duration ttl, int maxEntries, Logger logger) {
    if (maxEntries < 1) {
      throw new IllegalArgumentException("maxEntries must be >= 1");
    }
    this.ttl = ttl;
    this.maxEntries = maxEntries;
    this.logger = logger;
    this.store = new LinkedHashMap<>(16, 0.75f, false) {
      @Override
      protected boolean removeEldestEntry(Map.Entry<String, FingerprintRecord> eldest) {
        return size() > FingerprintStore.this.maxEntries;
      }
    };
    this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
      Thread thread = new Thread(r, "ja4-cleanup");
      thread.setDaemon(true);
      return thread;
    });
    scheduleCleanup();
  }

  public void put(FingerprintRecord record) {
    synchronized (store) {
      // Remove first so an updated record moves to the tail (newest) in insertion order
      // and survives eldest-entry eviction.
      store.remove(record.sessionId());
      store.put(record.sessionId(), record);
    }
  }

  public FingerprintRecord get(String sessionId) {
    FingerprintRecord record;
    synchronized (store) {
      record = store.get(sessionId);
    }
    if (record == null) {
      return null;
    }
    if (record.isExpired(Instant.now(), ttl)) {
      synchronized (store) {
        store.remove(sessionId);
      }
      return null;
    }
    return record;
  }

  public int size() {
    synchronized (store) {
      return store.size();
    }
  }

  public void shutdown() {
    scheduler.shutdownNow();
  }

  private void scheduleCleanup() {
    if (ttl == null || ttl.isZero() || ttl.isNegative()) {
      return;
    }
    long intervalSeconds = Math.max(30L, ttl.getSeconds() / 2L);
    scheduler.scheduleAtFixedRate(this::cleanupExpired, intervalSeconds, intervalSeconds,
        TimeUnit.SECONDS);
  }

  private void cleanupExpired() {
    try {
      Instant now = Instant.now();
      synchronized (store) {
        store.entrySet().removeIf(e -> e.getValue().isExpired(now, ttl));
      }
    } catch (Exception ex) {
      logger.log(Level.WARNING, "Failed to cleanup expired fingerprints", ex);
    }
  }
}
