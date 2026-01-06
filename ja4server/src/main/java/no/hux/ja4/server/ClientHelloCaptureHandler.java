package no.hux.ja4.server;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.util.AttributeKey;
import java.util.logging.Level;
import java.util.logging.Logger;
import no.hux.ja4.fingerprint.Ja4TlsFingerprint;

public final class ClientHelloCaptureHandler extends ChannelInboundHandlerAdapter {

  private static final int MAX_CAPTURE_BYTES = 64 * 1024;
  private final AttributeKey<ConnectionState> stateKey;
  private final Logger logger;
  private ByteBuf cumulation;
  private boolean done;

  public ClientHelloCaptureHandler(AttributeKey<ConnectionState> stateKey, Logger logger) {
    this.stateKey = stateKey;
    this.logger = logger;
  }

  @Override
  public void channelRead(ChannelHandlerContext ctx, Object msg) throws Exception {
    if (!done && msg instanceof ByteBuf buf) {
      if (cumulation == null) {
        cumulation = Unpooled.buffer();
      }
      if (cumulation.readableBytes() + buf.readableBytes() > MAX_CAPTURE_BYTES) {
        logger.log(Level.WARNING, "ClientHello capture exceeded {0} bytes", MAX_CAPTURE_BYTES);
        done = true;
        releaseBuffer();
        ctx.pipeline().remove(this);
      } else {
        cumulation.writeBytes(buf, buf.readerIndex(), buf.readableBytes());
      }
      try {
        ClientHelloInfo info = ClientHelloParser.tryParse(cumulation);
        if (info != null) {
          ConnectionState state = ctx.channel().attr(stateKey).get();
          if (state != null) {
            state.setClientHelloInfo(info);
            state.setJa4(Ja4TlsFingerprint.compute(info));
          }
          done = true;
          releaseBuffer();
          ctx.pipeline().remove(this);
        }
      } catch (Exception ex) {
        logger.log(Level.WARNING, "Failed to parse TLS ClientHello", ex);
        done = true;
        releaseBuffer();
      }
    }
    ctx.fireChannelRead(msg);
  }

  @Override
  public void channelInactive(ChannelHandlerContext ctx) throws Exception {
    releaseBuffer();
    super.channelInactive(ctx);
  }

  @Override
  public void handlerRemoved(ChannelHandlerContext ctx) throws Exception {
    releaseBuffer();
    super.handlerRemoved(ctx);
  }

  private void releaseBuffer() {
    if (cumulation != null) {
      cumulation.release();
      cumulation = null;
    }
  }
}
