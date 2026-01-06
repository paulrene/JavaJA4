package no.hux.ja4.fingerprint;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class Ja4Utils {

  // GREASE values are intentionally “random‑looking” TLS ciphers/extensions
  // defined in RFC 8701 to prevent protocol ossification. They’re not stable
  // identifiers of a client, so JA4 ignores them in counts/hashes.
  private static final Set<Integer> GREASE = Set.of(0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
      0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa);

  // These are the JA4 version tokens used in the a part of the JA4 TLS
  // fingerprint.
  private static final Map<String, String> TLS_MAPPER = Map.of("0x0002", "s2", "0x0300", "s3",
      "0x0301", "10", "0x0302", "11", "0x0303", "12", "0x0304", "13");

  private Ja4Utils() {
  }

  public static String hex(int value) {
    return String.format("0x%04x", value);
  }

  public static boolean isGrease(String value) {
    int parsed = parseHex(value);
    return GREASE.contains(parsed);
  }

  public static int parseHex(String value) {
    if (value.startsWith("0x") || value.startsWith("0X")) {
      return Integer.parseInt(value.substring(2), 16);
    }
    return Integer.parseInt(value, 16);
  }

  public static String tlsVersionCode(String value) {
    return TLS_MAPPER.getOrDefault(value, "00");
  }

  public static String shaEncode(List<String> values) {
    return shaEncode(String.join(",", values));
  }

  public static String shaEncode(String value) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
      StringBuilder sb = new StringBuilder();
      for (byte b : hash) {
        sb.append(String.format("%02x", b));
      }
      return sb.substring(0, 12);
    } catch (NoSuchAlgorithmException ex) {
      throw new IllegalStateException("SHA-256 not available", ex);
    }
  }

  public static HexSortResult sortHexValues(List<String> values, boolean sort,
      boolean isExtension) {
    List<String> filtered = new ArrayList<>();
    for (String value : values) {
      if (isGrease(value)) {
        continue;
      }
      String trimmed = value.startsWith("0x") ? value.substring(2) : value;
      if (isExtension && sort) {
        if ("0000".equals(trimmed) || "0010".equals(trimmed)) {
          continue;
        }
      }
      filtered.add(trimmed);
    }
    if (sort) {
      filtered.sort(Comparator.naturalOrder());
    }
    int actualLength = Math.min(filtered.size(), 99);
    String length = String.format("%02d", actualLength);
    String joined = String.join(",", filtered);
    String hash = filtered.isEmpty() ? "000000000000" : shaEncode(filtered);
    return new HexSortResult(joined, length, hash);
  }

  public static String getSupportedVersion(List<String> versions, String fallback) {
    int max = -1;
    for (String version : versions) {
      if (isGrease(version)) {
        continue;
      }
      int parsed = parseHex(version);
      if (parsed > max) {
        max = parsed;
      }
    }
    if (max == -1) {
      return fallback;
    }
    return hex(max);
  }

  public record HexSortResult(
    String raw,
    String length,
    String hash) {
  }
}
