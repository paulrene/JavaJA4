package no.hux.ja4.fingerprint;

import io.netty.handler.codec.http.FullHttpRequest;
import io.netty.handler.codec.http.HttpHeaders;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

public final class Ja4HttpFingerprint {
  
  private Ja4HttpFingerprint() {
  }

  public static String compute(FullHttpRequest request) {
    // JA4H: <method><version><cookie><referer><header_count><lang>_<headers_hash>_<cookie_fields_hash>_<cookie_values_hash>
    String method = request.method().name().toLowerCase(Locale.ROOT);
    method = method.length() >= 2 ? method.substring(0, 2) : method;

    // HTTP version (10/11/20) and cookie/referer flags go into the a-part.
    int version = request.protocolVersion().majorVersion() >= 2 ? 20
        : request.protocolVersion().minorVersion() == 0 ? 10 : 11;

    HttpHeaders headers = request.headers();
    boolean hasCookie = !headers.getAll("Cookie").isEmpty();
    boolean hasReferer = headers.contains("Referer");

    List<String> headerNames = new ArrayList<>();
    for (var entry : headers) {
      String name = entry.getKey();
      if (name == null) {
        continue;
      }
      if (!name.isEmpty() && name.charAt(0) == ':') {
        continue;
      }
      String lower = name.toLowerCase(Locale.ROOT);
      if (lower.startsWith("cookie") || "referer".equals(lower)) {
        continue;
      }
      headerNames.add(name);
    }

    int headerCount = Math.min(headerNames.size(), 99);
    String headerLen = String.format("%02d", headerCount);
    // Hash of header names (excluding cookies and referer).
    String headersHash = Ja4Utils.shaEncode(headerNames);

    // Accept-Language is normalized to a 4-char token for the a-part.
    String lang = "0000";
    String acceptLang = headers.get("Accept-Language");
    if (acceptLang != null && !acceptLang.isBlank()) {
      lang = httpLanguage(acceptLang);
    }

    List<String> cookieFields = new ArrayList<>();
    List<String> cookieValues = new ArrayList<>();
    for (String cookieHeader : headers.getAll("Cookie")) {
      String[] parts = cookieHeader.split(";");
      for (String part : parts) {
        String trimmed = part.trim();
        if (trimmed.isEmpty()) {
          continue;
        }
        cookieValues.add(trimmed);
        int eqIdx = trimmed.indexOf('=');
        String field = eqIdx >= 0 ? trimmed.substring(0, eqIdx).trim() : trimmed;
        if (!field.isEmpty()) {
          cookieFields.add(field);
        }
      }
    }

    cookieFields.sort(Comparator.naturalOrder());
    cookieValues.sort(Comparator.naturalOrder());

    // Hashes of cookie field names and values go into the c-part.
    String cookieFieldsHash = cookieFields.isEmpty() ? "000000000000"
        : Ja4Utils.shaEncode(cookieFields);
    String cookieValuesHash = cookieValues.isEmpty() ? "000000000000"
        : Ja4Utils.shaEncode(cookieValues);

    String cookieFlag = hasCookie ? "c" : "n";
    String refererFlag = hasReferer ? "r" : "n";

    return method + version + cookieFlag + refererFlag + headerLen + lang + "_" + headersHash + "_"
        + cookieFieldsHash + "_" + cookieValuesHash;
  }

  private static String httpLanguage(String header) {
    String lang = header.replace("-", "").replace(';', ',').toLowerCase(Locale.ROOT).split(",")[0];
    if (lang.length() > 4) {
      lang = lang.substring(0, 4);
    }
    if (lang.length() < 4) {
      lang = lang + "0".repeat(4 - lang.length());
    }
    return lang;
  }
}
