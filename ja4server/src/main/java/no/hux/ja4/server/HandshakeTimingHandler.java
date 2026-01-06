package no.hux.ja4.server;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.ssl.SslHandshakeCompletionEvent;
import io.netty.util.AttributeKey;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class HandshakeTimingHandler extends ChannelInboundHandlerAdapter {

  private final AttributeKey<ConnectionState> stateKey;
  private final Logger logger;

  public HandshakeTimingHandler(AttributeKey<ConnectionState> stateKey, Logger logger) {
    this.stateKey = stateKey;
    this.logger = logger;
  }

  @Override
  public void userEventTriggered(ChannelHandlerContext ctx, Object evt) throws Exception {
    if (evt instanceof SslHandshakeCompletionEvent event) {
      ConnectionState state = ctx.channel().attr(stateKey).get();
      if (event.isSuccess()) {
        if (state != null) {
          state.setHandshakeAtNanos(System.nanoTime());
        }
      } else {
        Throwable cause = event.cause();
        Level level = Level.WARNING;
        if (cause instanceof javax.net.ssl.SSLHandshakeException && cause.getMessage() != null
            && cause.getMessage().contains("certificate_unknown")) {
          level = Level.FINE;
        }
        logger.log(level, "TLS handshake failed", cause);
      }
    }
    super.userEventTriggered(ctx, evt);
  }
}
