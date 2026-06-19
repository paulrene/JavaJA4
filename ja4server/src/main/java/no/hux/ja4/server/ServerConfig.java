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
  private final int maxStoreEntries;
  private final boolean requireUuidSessionId;
  private final String apiUserPassword;
  private final int idleTimeoutSeconds;
  private final boolean enablePcap;
  private final String captureIface;

  public ServerConfig(String host, int port, String environment, Path certPath, Path keyPath,
      Path letsEncryptDir, String domain, Duration ttl, int maxContentLength,
      int maxStoreEntries, boolean requireUuidSessionId, String apiUserPassword,
      int idleTimeoutSeconds, boolean enablePcap, String captureIface) {
    this.host = host;
    this.port = port;
    this.environment = environment.toLowerCase(Locale.ROOT);
    this.certPath = certPath;
    this.keyPath = keyPath;
    this.letsEncryptDir = letsEncryptDir;
    this.domain = domain;
    this.ttl = ttl;
    this.maxContentLength = maxContentLength;
    this.maxStoreEntries = maxStoreEntries;
    this.requireUuidSessionId = requireUuidSessionId;
    this.apiUserPassword = apiUserPassword;
    this.idleTimeoutSeconds = idleTimeoutSeconds;
    this.enablePcap = enablePcap;
    this.captureIface = captureIface;
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

  public int getMaxStoreEntries() {
    return maxStoreEntries;
  }

  public boolean isRequireUuidSessionId() {
    return requireUuidSessionId;
  }

  public String getApiUserPassword() {
    return apiUserPassword;
  }

  public int getIdleTimeoutSeconds() {
    return idleTimeoutSeconds;
  }

  public boolean isEnablePcap() {
    return enablePcap;
  }

  public String getCaptureIface() {
    return captureIface;
  }

  public boolean isProd() {
    return "prod".equals(environment) || "production".equals(environment);
  }
}
