package no.hux.ja4.fingerprint;

import java.util.List;
import java.util.stream.Collectors;
import no.hux.ja4.server.ClientHelloInfo;

public final class Ja4TlsFingerprint {

  private Ja4TlsFingerprint() {
  }

  public static String compute(ClientHelloInfo info) {
    // JA4: t<ver><sni><cipher_count><ext_count><alpn>_<cipher_hash>_<ext_hash>
    String ptype = "t";
    List<String> extensions = info.getExtensions();
    List<String> ciphers = info.getCipherSuites();

    // Count non-GREASE extensions for the extension count field.
    int extCount = 0;
    for (String ext : extensions) {
      if (!Ja4Utils.isGrease(ext)) {
        extCount++;
      }
    }
    String extLen = String.format("%02d", Math.min(extCount, 99));

    // Hash over sorted cipher IDs and sorted extension IDs (with SNI/ALPN stripped
    // for the hash).
    Ja4Utils.HexSortResult sortedCiphers = Ja4Utils.sortHexValues(ciphers, true, false);
    Ja4Utils.HexSortResult sortedExtensions = Ja4Utils.sortHexValues(extensions, true, true);

    String sortedExtensionsRaw = sortedExtensions.raw();
    List<String> signatureAlgorithms = info.getSignatureAlgorithms();
    if (!signatureAlgorithms.isEmpty()) {
      // When present, signature algorithms are appended to the extension list before
      // hashing.
      String sig = signatureAlgorithms.stream().filter(s -> !Ja4Utils.isGrease(s))
          .map(s -> s.startsWith("0x") ? s.substring(2) : s).collect(Collectors.joining(","));
      sortedExtensionsRaw = sortedExtensionsRaw + "_" + sig;
    }

    String sortedExtensionsHash = extensions.isEmpty() ? "000000000000"
        : Ja4Utils.shaEncode(sortedExtensionsRaw);

    // TLS version is taken from supported_versions when present, else legacy
    // ClientHello version.
    String legacyHex = Ja4Utils.hex(info.getLegacyVersion());
    String versionHex = info.getSupportedVersions().isEmpty() ? legacyHex
        : Ja4Utils.getSupportedVersion(info.getSupportedVersions(), legacyHex);
    String version = Ja4Utils.tlsVersionCode(versionHex);

    // SNI presence and first ALPN token contribute to the a-part.
    String sni = info.getServerName() == null ? "i" : "d";

    String alpn = "00";
    if (!info.getAlpnProtocols().isEmpty()) {
      String protocol = info.getAlpnProtocols().get(0);
      if (protocol.length() > 2) {
        alpn = "" + protocol.charAt(0) + protocol.charAt(protocol.length() - 1);
      } else if (!protocol.isEmpty()) {
        alpn = protocol;
      }
      if (!alpn.isEmpty() && alpn.charAt(0) > 127) {
        alpn = "99";
      }
    }

    String cipherLen = sortedCiphers.length();
    String cipherHash = sortedCiphers.hash();
    String ja4 = ptype + version + sni + cipherLen + extLen + alpn + "_" + cipherHash + "_"
        + sortedExtensionsHash;
    return ja4;
  }
}
