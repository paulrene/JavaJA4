package no.hux.ja4.server;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.DecoderException;
import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.FullHttpResponse;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpHeaderValues;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.netty.handler.codec.http.HttpUtil;
import io.netty.handler.codec.http.HttpVersion;
import io.netty.handler.codec.http.QueryStringDecoder;
import io.netty.util.AttributeKey;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLHandshakeException;
import no.hux.ja4.fingerprint.Ja4HttpFingerprint;
import no.hux.ja4.fingerprint.Ja4LatencyFingerprint;
import no.hux.ja4.store.FingerprintRecord;
import no.hux.ja4.store.FingerprintStore;

public final class RequestHandler extends SimpleChannelInboundHandler<FullHttpRequest> {

  private static final String LOOKUP_PREFIX = "/api/lookup/";
  private static final int MAX_SESSION_ID_LENGTH = 256;
  private static final byte[] PIXEL_GIF = new byte[] { 71, 73, 70, 56, 57, 97, 1, 0, 1, 0,
      (byte) 128, 0, 0, 0, 0, 0, (byte) 255, (byte) 255, (byte) 255, 33, (byte) 249, 4, 1, 0, 0, 1,
      0, 44, 0, 0, 0, 0, 1, 0, 1, 0, 0, 2, 2, 68, 1, 0, 59 };

  private final FingerprintStore store;
  private final AttributeKey<ConnectionState> stateKey;
  private final Logger logger;

  public RequestHandler(FingerprintStore store, AttributeKey<ConnectionState> stateKey,
      Logger logger) {
    this.store = store;
    this.stateKey = stateKey;
    this.logger = logger;
  }

  @Override
  protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request) {
    if (HttpUtil.is100ContinueExpected(request)) {
      sendContinue(ctx);
    }

    QueryStringDecoder decoder = new QueryStringDecoder(request.uri());
    String path = decoder.path();

    try {
      if (path.startsWith(LOOKUP_PREFIX)) {
        handleLookup(ctx, request, path.substring(LOOKUP_PREFIX.length()));
      } else {
        handleFingerprint(ctx, request, path);
      }
    } catch (Exception ex) {
      logger.log(Level.WARNING, "Request handling failed", ex);
      sendJson(ctx, request, HttpResponseStatus.INTERNAL_SERVER_ERROR, errorJson("internal_error"));
    }
  }

  private void handleLookup(ChannelHandlerContext ctx, FullHttpRequest request,
      String rawSessionId) {
    String sessionId = normalizeSessionId(rawSessionId);
    if (sessionId == null) {
      sendJson(ctx, request, HttpResponseStatus.BAD_REQUEST, errorJson("invalid_session"));
      return;
    }
    FingerprintRecord record = store.get(sessionId);
    if (record == null) {
      sendJson(ctx, request, HttpResponseStatus.NOT_FOUND, errorJson("not_found"));
      return;
    }
    sendJson(ctx, request, HttpResponseStatus.OK, recordToJson(record));
  }

  private void handleFingerprint(ChannelHandlerContext ctx, FullHttpRequest request, String path) {
    String sessionId = normalizeSessionId(path.startsWith("/") ? path.substring(1) : path);
    if (sessionId == null) {
      sendJson(ctx, request, HttpResponseStatus.BAD_REQUEST, errorJson("invalid_session"));
      return;
    }

    ConnectionState state = ctx.channel().attr(stateKey).get();
    if (state != null) {
      state.markFirstRequest(System.nanoTime());
    }
    String ja4 = state != null ? state.getJa4() : null;
    String ja4h = Ja4HttpFingerprint.compute(request);
    String ja4l = Ja4LatencyFingerprint.compute(state);

    String ip = null;
    if (ctx.channel().remoteAddress() instanceof InetSocketAddress remote) {
      ip = remote.getAddress().getHostAddress();
    }
    String userAgent = request.headers().get("User-Agent");

    FingerprintRecord record = new FingerprintRecord(sessionId, Instant.now(), ja4, ja4h, ja4l, ip,
        userAgent);
    store.put(record);

    sendGif(ctx, request);
  }

  private String normalizeSessionId(String raw) {
    if (raw == null) {
      return null;
    }
    String trimmed = raw.trim();
    if (trimmed.isEmpty() || trimmed.contains("/")) {
      return null;
    }
    String decoded = URLDecoder.decode(trimmed, StandardCharsets.UTF_8);
    if (decoded.isEmpty() || decoded.contains("/") || decoded.length() > MAX_SESSION_ID_LENGTH) {
      return null;
    }
    return decoded;
  }

  private void sendContinue(ChannelHandlerContext ctx) {
    FullHttpResponse response = new io.netty.handler.codec.http.DefaultFullHttpResponse(
        HttpVersion.HTTP_1_1, HttpResponseStatus.CONTINUE);
    ctx.writeAndFlush(response);
  }

  private void sendJson(ChannelHandlerContext ctx, FullHttpRequest request,
      HttpResponseStatus status, String body) {
    ByteBuf content = Unpooled.copiedBuffer(body, StandardCharsets.UTF_8);
    FullHttpResponse response = new io.netty.handler.codec.http.DefaultFullHttpResponse(
        request.protocolVersion(), status, content);
    response.headers().set(HttpHeaderNames.CONTENT_TYPE, "application/json; charset=UTF-8");
    response.headers().setInt(HttpHeaderNames.CONTENT_LENGTH, content.readableBytes());
    response.headers().set("X-Content-Type-Options", "nosniff");
    response.headers().set(HttpHeaderNames.CACHE_CONTROL,
        "no-store, no-cache, must-revalidate, max-age=0");
    response.headers().set(HttpHeaderNames.PRAGMA, "no-cache");
    response.headers().set(HttpHeaderNames.EXPIRES, "0");
    boolean keepAlive = HttpUtil.isKeepAlive(request);
    if (keepAlive) {
      response.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.KEEP_ALIVE);
      ctx.writeAndFlush(response);
    } else {
      ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
    }
  }

  private void sendGif(ChannelHandlerContext ctx, FullHttpRequest request) {
    ByteBuf content = Unpooled.wrappedBuffer(PIXEL_GIF);
    FullHttpResponse response = new io.netty.handler.codec.http.DefaultFullHttpResponse(
        request.protocolVersion(), HttpResponseStatus.OK, content);
    response.headers().set(HttpHeaderNames.CONTENT_TYPE, "image/gif");
    response.headers().setInt(HttpHeaderNames.CONTENT_LENGTH, content.readableBytes());
    response.headers().set("X-Content-Type-Options", "nosniff");
    response.headers().set(HttpHeaderNames.CACHE_CONTROL,
        "no-store, no-cache, must-revalidate, max-age=0");
    response.headers().set(HttpHeaderNames.PRAGMA, "no-cache");
    response.headers().set(HttpHeaderNames.EXPIRES, "0");
    boolean keepAlive = HttpUtil.isKeepAlive(request);
    if (keepAlive) {
      response.headers().set(HttpHeaderNames.CONNECTION, HttpHeaderValues.KEEP_ALIVE);
      ctx.writeAndFlush(response);
    } else {
      ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE);
    }
  }

  private static String recordToJson(FingerprintRecord record) {
    StringBuilder sb = new StringBuilder();
    sb.append('{');
    appendField(sb, "sessionId", record.sessionId());
    sb.append(',');
    appendField(sb, "timestamp",
        java.time.format.DateTimeFormatter.ISO_INSTANT.format(record.timestamp()));
    sb.append(',');
    appendField(sb, "ip", record.ip());
    sb.append(',');
    appendField(sb, "userAgent", record.userAgent());
    sb.append(',');
    sb.append("\"fingerprints\":{");
    appendField(sb, "ja4", record.ja4());
    sb.append(',');
    appendField(sb, "ja4h", record.ja4h());
    sb.append(',');
    appendField(sb, "ja4l", record.ja4l());
    sb.append('}');
    sb.append('}');
    return sb.toString();
  }

  private static String errorJson(String message) {
    StringBuilder sb = new StringBuilder();
    sb.append('{');
    appendField(sb, "error", message);
    sb.append('}');
    return sb.toString();
  }

  private static void appendField(StringBuilder sb, String key, String value) {
    sb.append('"').append(escape(key)).append('"').append(':');
    if (value == null) {
      sb.append("null");
    } else {
      sb.append('"').append(escape(value)).append('"');
    }
  }

  private static String escape(String value) {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      switch (c) {
      case '"' -> sb.append("\\\"");
      case '\\' -> sb.append("\\\\");
      case '\b' -> sb.append("\\b");
      case '\f' -> sb.append("\\f");
      case '\n' -> sb.append("\\n");
      case '\r' -> sb.append("\\r");
      case '\t' -> sb.append("\\t");
      default -> {
        if (c < 0x20) {
          sb.append(String.format("\\u%04x", (int) c));
        } else {
          sb.append(c);
        }
      }
      }
    }
    return sb.toString();
  }

  @Override
  public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
    Throwable root = cause instanceof DecoderException && cause.getCause() != null
        ? cause.getCause()
        : cause;
    if (root instanceof SSLHandshakeException && root.getMessage() != null
        && root.getMessage().contains("certificate_unknown")) {
      logger.log(Level.FINE, "TLS handshake failed (client did not trust certificate)", root);
    } else {
      logger.log(Level.WARNING, "Unhandled exception in pipeline", root);
    }
    ctx.close();
  }
}
