package no.hux.ja4.server;

import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.handler.codec.http.HttpObjectAggregator;
import io.netty.handler.codec.http.HttpServerCodec;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.timeout.IdleStateHandler;
import io.netty.util.AttributeKey;
import io.netty.util.internal.logging.InternalLoggerFactory;
import io.netty.util.internal.logging.JdkLoggerFactory;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import no.hux.ja4.capture.PacketCaptureService;
import no.hux.ja4.capture.TcpInfoStore;
import no.hux.ja4.store.FingerprintStore;

public final class Ja4Server {
  private final ServerConfig config;
  private final Logger logger;

  public Ja4Server(ServerConfig config, Logger logger) {
    this.config = config;
    this.logger = logger;
  }

  public void start() throws Exception {
    InternalLoggerFactory.setDefaultFactory(JdkLoggerFactory.INSTANCE);

    Path certPath = resolveCertPath(config);
    Path keyPath = resolveKeyPath(config);
    SslContext sslContext = SslContextBuilder.forServer(certPath.toFile(), keyPath.toFile())
        .build();

    FingerprintStore store = new FingerprintStore(config.getTtl(), config.getMaxStoreEntries(),
        logger);
    AttributeKey<ConnectionState> stateKey = AttributeKey.valueOf("ja4State");
    long serverStartMillis = System.currentTimeMillis();

    InetSocketAddress bindAddress = resolveIpv4Address(config.getHost(), config.getPort());

    TcpInfoStore tcpInfoStore = null;
    PacketCaptureService captureService = null;
    if (config.isEnablePcap()) {
      tcpInfoStore = new TcpInfoStore(logger);
      captureService = new PacketCaptureService(config.getPort(), bindAddress.getAddress(),
          config.getCaptureIface(), tcpInfoStore, logger);
      captureService.start();
    }
    final TcpInfoStore tcpInfoStoreRef = tcpInfoStore;

    EventLoopGroup bossGroup = new MultiThreadIoEventLoopGroup(1, NioIoHandler.newFactory());
    EventLoopGroup workerGroup = new MultiThreadIoEventLoopGroup(NioIoHandler.newFactory());
    try {
      ServerBootstrap bootstrap = new ServerBootstrap();
      bootstrap.group(bossGroup, workerGroup).channel(NioServerSocketChannel.class)
          .childHandler(new ChannelInitializer<SocketChannel>() {
            @Override
            protected void initChannel(SocketChannel ch) {
              int idleTimeoutSeconds = config.getIdleTimeoutSeconds();
              if (idleTimeoutSeconds > 0) {
                ch.pipeline().addLast("idleState",
                    new IdleStateHandler(0, 0, idleTimeoutSeconds, TimeUnit.SECONDS));
                ch.pipeline().addLast("idleClose", new IdleConnectionHandler(logger));
              }
              ch.pipeline().addLast("state", new ConnectionStateHandler(stateKey));
              ch.pipeline().addLast("clientHello", new ClientHelloCaptureHandler(stateKey, logger));
              ch.pipeline().addLast("ssl", sslContext.newHandler(ch.alloc()));
              ch.pipeline().addLast("handshake", new HandshakeTimingHandler(stateKey, logger));
              ch.pipeline().addLast("httpCodec", new HttpServerCodec());
              ch.pipeline().addLast("aggregator",
                  new HttpObjectAggregator(config.getMaxContentLength()));
              if (config.getApiUserPassword() != null) {
                ch.pipeline().addLast(new BasicAuthHandler(config, "/api"));
              }
              ch.pipeline().addLast("handler", new RequestHandler(store, stateKey, logger,
                  serverStartMillis, config.isRequireUuidSessionId(), tcpInfoStoreRef));
            }
          });

      Channel channel = bootstrap.bind(bindAddress).sync().channel();
      logger.info("JA4 server listening on https://" + config.getHost() + ":" + config.getPort());
      channel.closeFuture().sync();
    } finally {
      if (captureService != null) {
        captureService.stop();
      }
      if (tcpInfoStore != null) {
        tcpInfoStore.shutdown();
      }
      store.shutdown();
      bossGroup.shutdownGracefully();
      workerGroup.shutdownGracefully();
    }
  }

  private Path resolveCertPath(ServerConfig config) {
    Path certPath = config.getCertPath();
    if (certPath != null) {
      ensureFileExists(certPath, "certificate");
      return certPath;
    }
    if (config.isProd()) {
      Path resolved = config.getLetsEncryptDir().resolve(config.getDomain())
          .resolve("fullchain.pem");
      ensureFileExists(resolved, "certificate");
      return resolved;
    }
    Path resolved = Path.of("certs", "local", "server.pem");
    ensureFileExists(resolved, "certificate");
    return resolved;
  }

  private Path resolveKeyPath(ServerConfig config) {
    Path keyPath = config.getKeyPath();
    if (keyPath != null) {
      ensureFileExists(keyPath, "private key");
      return keyPath;
    }
    if (config.isProd()) {
      Path resolved = config.getLetsEncryptDir().resolve(config.getDomain()).resolve("privkey.pem");
      ensureFileExists(resolved, "private key");
      return resolved;
    }
    Path resolved = Path.of("certs", "local", "server.key");
    ensureFileExists(resolved, "private key");
    return resolved;
  }

  private void ensureFileExists(Path path, String label) {
    if (!Files.exists(path)) {
      logger.log(Level.SEVERE, "Missing {0} at {1}", new Object[] { label, path });
      throw new IllegalStateException("Missing " + label + " file: " + path);
    }
  }

  private InetSocketAddress resolveIpv4Address(String host, int port) throws Exception {
    InetAddress[] addresses = InetAddress.getAllByName(host);
    for (InetAddress address : addresses) {
      if (address instanceof Inet4Address) {
        return new InetSocketAddress(address, port);
      }
    }
    throw new IllegalArgumentException("Host must resolve to an IPv4 address: " + host);
  }
}
