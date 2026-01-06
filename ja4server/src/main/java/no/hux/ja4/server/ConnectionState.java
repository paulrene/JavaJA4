package no.hux.ja4.server;

public final class ConnectionState {

  private final long acceptedAtNanos;
  private volatile long handshakeAtNanos;
  private volatile long firstRequestAtNanos;
  private volatile ClientHelloInfo clientHelloInfo;
  private volatile String ja4;

  public ConnectionState(long acceptedAtNanos) {
    this.acceptedAtNanos = acceptedAtNanos;
  }

  public long acceptedAtNanos() {
    return acceptedAtNanos;
  }

  public long handshakeAtNanos() {
    return handshakeAtNanos;
  }

  public void setHandshakeAtNanos(long handshakeAtNanos) {
    this.handshakeAtNanos = handshakeAtNanos;
  }

  public long firstRequestAtNanos() {
    return firstRequestAtNanos;
  }

  public boolean markFirstRequest(long nowNanos) {
    if (firstRequestAtNanos == 0L) {
      firstRequestAtNanos = nowNanos;
      return true;
    }
    return false;
  }

  public ClientHelloInfo clientHelloInfo() {
    return clientHelloInfo;
  }

  public void setClientHelloInfo(ClientHelloInfo clientHelloInfo) {
    this.clientHelloInfo = clientHelloInfo;
  }

  public String ja4() {
    return ja4;
  }

  public void setJa4(String ja4) {
    this.ja4 = ja4;
  }
}
