package no.hux.ja4.server;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.util.AttributeKey;

public final class ConnectionStateHandler extends ChannelInboundHandlerAdapter {

  private final AttributeKey<ConnectionState> stateKey;

  public ConnectionStateHandler(AttributeKey<ConnectionState> stateKey) {
    this.stateKey = stateKey;
  }

  @Override
  public void channelActive(ChannelHandlerContext ctx) throws Exception {
    ConnectionState state = new ConnectionState(System.nanoTime());
    ctx.channel().attr(stateKey).set(state);
    super.channelActive(ctx);
  }
}
