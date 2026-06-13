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
import io.netty.handler.ssl.NotSslRecordException;
import io.netty.handler.ssl.SslHandshakeTimeoutException;
import io.netty.util.AttributeKey;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.channels.ClosedChannelException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import no.hux.ja4.fingerprint.Ja4HttpFingerprint;
import no.hux.ja4.fingerprint.Ja4LatencyFingerprint;
import no.hux.ja4.store.FingerprintRecord;
import no.hux.ja4.store.FingerprintStore;

public final class RequestHandler extends SimpleChannelInboundHandler<FullHttpRequest> {
  private static final String LOOKUP_PREFIX = "/api/lookup/";
  private static final int MAX_SESSION_ID_LENGTH = 256;
  private static final int CANONICAL_UUID_LENGTH = 36;
  private static final byte[] PIXEL_GIF = new byte[] { 71, 73, 70, 56, 57, 97, 1, 0, 1, 0,
      (byte) 128, 0, 0, 0, 0, 0, (byte) 255, (byte) 255, (byte) 255, 33, (byte) 249, 4, 1, 0, 0, 1,
      0, 44, 0, 0, 0, 0, 1, 0, 1, 0, 0, 2, 2, 68, 1, 0, 59 };

  private final FingerprintStore store;
  private final AttributeKey<ConnectionState> stateKey;
  private final Logger logger;
  private final long serverStartMillis;
  private final boolean requireUuidSessionId;

  public RequestHandler(FingerprintStore store, AttributeKey<ConnectionState> stateKey,
      Logger logger, long serverStartMillis, boolean requireUuidSessionId) {
    this.store = store;
    this.stateKey = stateKey;
    this.logger = logger;
    this.serverStartMillis = serverStartMillis;
    this.requireUuidSessionId = requireUuidSessionId;
  }

  @Override
  protected void channelRead0(ChannelHandlerContext ctx, FullHttpRequest request) {
    if (HttpUtil.is100ContinueExpected(request)) {
      sendContinue(ctx);
    }

    try {
      QueryStringDecoder decoder = new QueryStringDecoder(request.uri());
      String path = decoder.path();

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
    sendJson(ctx, request, HttpResponseStatus.OK, recordToJson(record, uptimeSeconds()));
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
    if (requireUuidSessionId && !isCanonicalUuid(decoded)) {
      return null;
    }
    return decoded;
  }

  private static boolean isCanonicalUuid(String value) {
    // UUID.fromString alone accepts non-canonical forms with shorter hex groups on some
    // JDKs, so we additionally enforce the 36-character canonical 8-4-4-4-12 layout.
    if (value.length() != CANONICAL_UUID_LENGTH) {
      return false;
    }
    try {
      UUID.fromString(value);
      return true;
    } catch (IllegalArgumentException ex) {
      return false;
    }
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

  private static String recordToJson(FingerprintRecord record, long uptimeSeconds) {
    StringBuilder sb = new StringBuilder();
    sb.append('{');
    appendField(sb, "sessionId", record.sessionId());
    sb.append(',');
    appendField(sb, "timestamp",
        java.time.format.DateTimeFormatter.ISO_INSTANT.format(record.timestamp()));
    sb.append(',');
    appendNumericField(sb, "uptimeSeconds", uptimeSeconds);
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

  private static void appendNumericField(StringBuilder sb, String key, long value) {
    sb.append('"').append(escape(key)).append('"').append(':').append(value);
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

  private long uptimeSeconds() {
    long elapsedMillis = System.currentTimeMillis() - serverStartMillis;
    if (elapsedMillis <= 0L) {
      return 0L;
    }
    return elapsedMillis / 1000L;
  }

  @Override
  public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
    Throwable root = cause instanceof DecoderException && cause.getCause() != null
        ? cause.getCause()
        : cause;
    if (isBenignNetworkException(root)) {
      logger.log(Level.FINE, "Benign network/TLS exception", root);
    } else {
      logger.log(Level.WARNING, "Unhandled exception in pipeline", root);
    }
    ctx.close();
  }

  static boolean isBenignNetworkException(Throwable cause) {
    if (cause == null) {
      return false;
    }
    if (cause instanceof NotSslRecordException
        || cause instanceof SslHandshakeTimeoutException
        || cause instanceof ClosedChannelException) {
      return true;
    }
    if (cause instanceof SSLHandshakeException) {
      return true;
    }
    if (cause instanceof SSLException) {
      String msg = cause.getMessage();
      if (msg != null && (msg.contains("Received close_notify")
          || msg.contains("Connection reset")
          || msg.contains("closed already"))) {
        return true;
      }
    }
    if (cause instanceof IOException) {
      String msg = cause.getMessage();
      if (msg != null && (msg.contains("Connection reset")
          || msg.contains("Broken pipe")
          || msg.contains("Connection timed out")
          || msg.contains("closed by the remote host"))) {
        return true;
      }
    }
    return false;
  }
}
