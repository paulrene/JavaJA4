package no.hux.ja4.server;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.util.AttributeKey;
import java.net.InetSocketAddress;
import no.hux.ja4.capture.TcpInfoStore;

public final class ConnectionStateHandler extends ChannelInboundHandlerAdapter {

  private final AttributeKey<ConnectionState> stateKey;
  private final TcpInfoStore tcpInfoStore;

  public ConnectionStateHandler(AttributeKey<ConnectionState> stateKey, TcpInfoStore tcpInfoStore) {
    this.stateKey = stateKey;
    this.tcpInfoStore = tcpInfoStore;
  }

  @Override
  public void channelActive(ChannelHandlerContext ctx) throws Exception {
    ConnectionState state = new ConnectionState(System.nanoTime());
    if (tcpInfoStore != null
        && ctx.channel().remoteAddress() instanceof InetSocketAddress remote) {
      // Latch a reference to the (possibly still-populating) handshake record
      // while the SYN is fresh in the store. Holding the reference keeps the
      // correlation valid for the connection's whole lifetime, so later TTL
      // eviction can't break JA4T/JA4L on keep-alive connections; the capture
      // thread fills in the fields on this same object as packets arrive.
      state.setHandshake(
          tcpInfoStore.getOrCreate(remote.getAddress().getHostAddress(), remote.getPort()));
    }
    ctx.channel().attr(stateKey).set(state);
    super.channelActive(ctx);
  }
}
