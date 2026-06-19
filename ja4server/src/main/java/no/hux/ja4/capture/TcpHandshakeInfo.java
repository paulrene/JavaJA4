package no.hux.ja4.capture;

/**
 * Mutable per-connection holder for TCP handshake data observed out-of-band via
 * packet capture, keyed by the client {@code ip:port}.
 *
 * <p>Fields are written only by the single capture thread and read by Netty
 * worker threads, so they are {@code volatile} for safe publication. Timestamps
 * are epoch microseconds taken from the libpcap packet timestamp.
 */
public final class TcpHandshakeInfo {

  private final long createdNanos;

  private volatile String ja4t;
  private volatile int clientTtl;
  private volatile long synMicros;
  private volatile long synAckMicros;
  private volatile long ackMicros;

  public TcpHandshakeInfo(long createdNanos) {
    this.createdNanos = createdNanos;
  }

  public long getCreatedNanos() {
    return createdNanos;
  }

  public String getJa4t() {
    return ja4t;
  }

  public void setJa4t(String ja4t) {
    this.ja4t = ja4t;
  }

  public int getClientTtl() {
    return clientTtl;
  }

  public void setClientTtl(int clientTtl) {
    this.clientTtl = clientTtl;
  }

  public long getSynMicros() {
    return synMicros;
  }

  public void setSynMicros(long synMicros) {
    this.synMicros = synMicros;
  }

  public long getSynAckMicros() {
    return synAckMicros;
  }

  public void setSynAckMicros(long synAckMicros) {
    this.synAckMicros = synAckMicros;
  }

  public long getAckMicros() {
    return ackMicros;
  }

  public void setAckMicros(long ackMicros) {
    this.ackMicros = ackMicros;
  }

  /**
   * Computes the client-side JA4L ({@code <latency>_<ttl>}) once the client's
   * handshake-completing ACK has been observed.
   *
   * <p>Latency is half of the (ACK - SYN/ACK) delta in microseconds, matching the
   * FoxIO reference. Returns {@code null} until both timestamps are available.
   */
  public String computeJa4l() {
    long synAck = synAckMicros;
    long ack = ackMicros;
    if (synAck == 0L || ack == 0L) {
      return null;
    }
    long latency = Math.max(0L, (ack - synAck) / 2L);
    return latency + "_" + clientTtl;
  }
}
