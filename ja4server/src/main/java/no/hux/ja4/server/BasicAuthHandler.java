package no.hux.ja4.server;

import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.codec.http.DefaultFullHttpResponse;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpVersion;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public final class BasicAuthHandler extends ChannelInboundHandlerAdapter {

  private final String expectedAuthHeader;
  private final String protectedPath;

  public BasicAuthHandler(ServerConfig config, String protectedPath) {
    String token = config.getApiUserPassword();
    if (token.indexOf(":") == -1) {
      throw new IllegalArgumentException("ApiUserPassword is not on the form user:password");
    }
    this.expectedAuthHeader = "Basic "
        + Base64.getEncoder().encodeToString(token.getBytes(StandardCharsets.UTF_8));
    this.protectedPath = protectedPath;
  }

  @Override
  public void channelRead(ChannelHandlerContext ctx, Object msg) {
    if (!(msg instanceof FullHttpRequest request)) {
      ctx.fireChannelRead(msg);
      return;
    }

    if (!request.uri().startsWith(protectedPath)) {
      ctx.fireChannelRead(msg);
      return;
    }

    String authHeader = request.headers().get(HttpHeaderNames.AUTHORIZATION);

    if (!expectedAuthHeader.equals(authHeader)) {
      sendUnauthorized(ctx);
      request.release();
      return;
    }

    ctx.fireChannelRead(msg);
  }

  private void sendUnauthorized(ChannelHandlerContext ctx) {
    FullHttpResponse response = new DefaultFullHttpResponse(HttpVersion.HTTP_1_1,
        HttpResponseStatus.UNAUTHORIZED);

    response.headers().set(HttpHeaderNames.WWW_AUTHENTICATE, "Basic realm=\"lookuprealm\"");
    response.headers().set(HttpHeaderNames.CONTENT_LENGTH, 0);

    ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
  }
}