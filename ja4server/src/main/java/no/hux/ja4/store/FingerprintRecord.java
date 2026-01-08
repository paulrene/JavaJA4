package no.hux.ja4.store;

import java.time.Duration;
import java.time.Instant;

public record FingerprintRecord(
  String sessionId,
  Instant timestamp,
  String ja4,
  String ja4h,
  String ja4l,
  String ip,
  String userAgent) {

  public boolean isExpired(Instant now, Duration ttl) {
    return ttl != null && !ttl.isZero() && timestamp().plus(ttl).isBefore(now);
  }
}
