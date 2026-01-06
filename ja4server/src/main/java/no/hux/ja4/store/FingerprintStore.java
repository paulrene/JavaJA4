package no.hux.ja4.store;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class FingerprintStore {

  private final Map<String, FingerprintRecord> store = new ConcurrentHashMap<>();
  private final Duration ttl;
  private final Logger logger;
  private final ScheduledExecutorService scheduler;

  public FingerprintStore(Duration ttl, Logger logger) {
    this.ttl = ttl;
    this.logger = logger;
    this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
      Thread thread = new Thread(r, "ja4-cleanup");
      thread.setDaemon(true);
      return thread;
    });
    scheduleCleanup();
  }

  public void put(FingerprintRecord record) {
    store.put(record.sessionId(), record);
  }

  public FingerprintRecord get(String sessionId) {
    FingerprintRecord record = store.get(sessionId);
    if (record == null) {
      return null;
    }
    if (record.isExpired(Instant.now(), ttl)) {
      store.remove(sessionId);
      return null;
    }
    return record;
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
      for (var entry : store.entrySet()) {
        if (entry.getValue().isExpired(now, ttl)) {
          store.remove(entry.getKey());
        }
      }
    } catch (Exception ex) {
      logger.log(Level.WARNING, "Failed to cleanup expired fingerprints", ex);
    }
  }
}
