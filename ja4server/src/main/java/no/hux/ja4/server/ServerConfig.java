package no.hux.ja4.server;

import java.nio.file.Path;
import java.time.Duration;
import java.util.Locale;

public final class ServerConfig {

  private final String host;
  private final int port;
  private final String environment;
  private final Path certPath;
  private final Path keyPath;
  private final Path letsEncryptDir;
  private final String domain;
  private final Duration ttl;
  private final int maxContentLength;

  public ServerConfig(String host, int port, String environment, Path certPath, Path keyPath,
      Path letsEncryptDir, String domain, Duration ttl, int maxContentLength) {
    this.host = host;
    this.port = port;
    this.environment = environment.toLowerCase(Locale.ROOT);
    this.certPath = certPath;
    this.keyPath = keyPath;
    this.letsEncryptDir = letsEncryptDir;
    this.domain = domain;
    this.ttl = ttl;
    this.maxContentLength = maxContentLength;
  }

  public String getHost() {
    return host;
  }

  public int getPort() {
    return port;
  }

  public String getEnvironment() {
    return environment;
  }

  public Path getCertPath() {
    return certPath;
  }

  public Path getKeyPath() {
    return keyPath;
  }

  public Path getLetsEncryptDir() {
    return letsEncryptDir;
  }

  public String getDomain() {
    return domain;
  }

  public Duration getTtl() {
    return ttl;
  }

  public int getMaxContentLength() {
    return maxContentLength;
  }

  public boolean isProd() {
    return "prod".equals(environment) || "production".equals(environment);
  }
}
