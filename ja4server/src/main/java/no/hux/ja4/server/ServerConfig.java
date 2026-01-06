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

  public String host() {
    return host;
  }

  public int port() {
    return port;
  }

  public String environment() {
    return environment;
  }

  public Path certPath() {
    return certPath;
  }

  public Path keyPath() {
    return keyPath;
  }

  public Path letsEncryptDir() {
    return letsEncryptDir;
  }

  public String domain() {
    return domain;
  }

  public Duration ttl() {
    return ttl;
  }

  public int maxContentLength() {
    return maxContentLength;
  }

  public boolean isProd() {
    return "prod".equals(environment) || "production".equals(environment);
  }
}
