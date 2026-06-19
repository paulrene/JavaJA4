package no.hux.ja4.server;

public final class ConnectionState {

  private final long acceptedAtNanos;
  private volatile long handshakeAtNanos;
  private volatile long firstRequestAtNanos;
  private volatile ClientHelloInfo clientHelloInfo;
  private volatile String ja4;
  private volatile no.hux.ja4.capture.TcpHandshakeInfo handshake;

  public ConnectionState(long acceptedAtNanos) {
    this.acceptedAtNanos = acceptedAtNanos;
  }

  public long getAcceptedAtNanos() {
    return acceptedAtNanos;
  }

  public long getHandshakeAtNanos() {
    return handshakeAtNanos;
  }

  public void setHandshakeAtNanos(long handshakeAtNanos) {
    this.handshakeAtNanos = handshakeAtNanos;
  }

  public long getFirstRequestAtNanos() {
    return firstRequestAtNanos;
  }

  public boolean markFirstRequest(long nowNanos) {
    if (firstRequestAtNanos == 0L) {
      firstRequestAtNanos = nowNanos;
      return true;
    }
    return false;
  }

  public ClientHelloInfo getClientHelloInfo() {
    return clientHelloInfo;
  }

  public void setClientHelloInfo(ClientHelloInfo clientHelloInfo) {
    this.clientHelloInfo = clientHelloInfo;
  }

  public String getJa4() {
    return ja4;
  }

  public void setJa4(String ja4) {
    this.ja4 = ja4;
  }

  /**
   * Out-of-band TCP handshake data for this connection, latched at connect time
   * so the request handler can read JA4T / real JA4L regardless of when (or how
   * often) requests arrive on a keep-alive connection. {@code null} when packet
   * capture is disabled.
   */
  public no.hux.ja4.capture.TcpHandshakeInfo getHandshake() {
    return handshake;
  }

  public void setHandshake(no.hux.ja4.capture.TcpHandshakeInfo handshake) {
    this.handshake = handshake;
  }
}
