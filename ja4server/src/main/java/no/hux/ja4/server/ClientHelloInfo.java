package no.hux.ja4.server;

import java.util.Collections;
import java.util.List;

public final class ClientHelloInfo {

  private final int legacyVersion;
  private final List<String> cipherSuites;
  private final List<String> extensions;
  private final List<String> supportedVersions;
  private final List<String> signatureAlgorithms;
  private final List<String> alpnProtocols;
  private final String serverName;

  public ClientHelloInfo(int legacyVersion, List<String> cipherSuites, List<String> extensions,
      List<String> supportedVersions, List<String> signatureAlgorithms, List<String> alpnProtocols,
      String serverName) {
    this.legacyVersion = legacyVersion;
    this.cipherSuites = List.copyOf(cipherSuites);
    this.extensions = List.copyOf(extensions);
    this.supportedVersions = List.copyOf(supportedVersions);
    this.signatureAlgorithms = List.copyOf(signatureAlgorithms);
    this.alpnProtocols = List.copyOf(alpnProtocols);
    this.serverName = serverName;
  }

  public int legacyVersion() {
    return legacyVersion;
  }

  public List<String> cipherSuites() {
    return Collections.unmodifiableList(cipherSuites);
  }

  public List<String> extensions() {
    return Collections.unmodifiableList(extensions);
  }

  public List<String> supportedVersions() {
    return Collections.unmodifiableList(supportedVersions);
  }

  public List<String> signatureAlgorithms() {
    return Collections.unmodifiableList(signatureAlgorithms);
  }

  public List<String> alpnProtocols() {
    return Collections.unmodifiableList(alpnProtocols);
  }

  public String serverName() {
    return serverName;
  }
}
