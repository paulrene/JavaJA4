package no.hux.ja4.store;

import java.time.Duration;
import java.time.Instant;

public final class FingerprintRecord {

  private final String sessionId;
  private final Instant timestamp;
  private final String ja4;
  private final String ja4h;
  private final String ja4l;
  private final String ip;
  private final String userAgent;

  public FingerprintRecord(String sessionId, Instant timestamp, String ja4, String ja4h,
      String ja4l, String ip, String userAgent) {
    this.sessionId = sessionId;
    this.timestamp = timestamp;
    this.ja4 = ja4;
    this.ja4h = ja4h;
    this.ja4l = ja4l;
    this.ip = ip;
    this.userAgent = userAgent;
  }

  public String sessionId() {
    return sessionId;
  }

  public Instant timestamp() {
    return timestamp;
  }

  public String ja4() {
    return ja4;
  }

  public String ja4h() {
    return ja4h;
  }

  public String ja4l() {
    return ja4l;
  }

  public String ip() {
    return ip;
  }

  public String userAgent() {
    return userAgent;
  }

  public boolean isExpired(Instant now, Duration ttl) {
    return ttl != null && !ttl.isZero() && timestamp.plus(ttl).isBefore(now);
  }
}
