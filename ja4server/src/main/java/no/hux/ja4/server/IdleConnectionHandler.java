package no.hux.ja4.server;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.timeout.IdleStateEvent;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class IdleConnectionHandler extends ChannelInboundHandlerAdapter {

  private final Logger logger;

  public IdleConnectionHandler(Logger logger) {
    this.logger = logger;
  }

  @Override
  public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
    if (evt instanceof IdleStateEvent) {
      logger.log(Level.FINE, "Closing idle connection {0}", ctx.channel().remoteAddress());
      ctx.close();
      return;
    }
    super.userEventTriggered(ctx, evt);
  }
}
