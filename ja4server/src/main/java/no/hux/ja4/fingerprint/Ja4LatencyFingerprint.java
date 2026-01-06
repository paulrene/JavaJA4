package no.hux.ja4.fingerprint;

import no.hux.ja4.server.ConnectionState;

public final class Ja4LatencyFingerprint {
  
  private Ja4LatencyFingerprint() {
  }

  /**
   * Beware: This is not a true JA4L fingerprint, but an estimate done by taking
   * half of the elapsed microseconds between connection accept and first HTTP
   * request.
   */
  public static String compute(ConnectionState state) {
    // JA4L: <latency>_<ttl> derived from accept->first request timing (ttl is 0
    // here).
    if (state == null) {
      return null;
    }
    long firstRequest = state.firstRequestAtNanos();
    long accepted = state.acceptedAtNanos();
    if (firstRequest == 0L || accepted == 0L) {
      return null;
    }
    long elapsedMicros = Math.max(0L, (firstRequest - accepted) / 1_000L);
    // JA4L defines latency as half of the observed client->server timing delta.
    long latency = elapsedMicros / 2L;
    return latency + "_0";
  }
}
