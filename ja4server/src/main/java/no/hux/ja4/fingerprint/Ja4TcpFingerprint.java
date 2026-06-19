package no.hux.ja4.fingerprint;

import java.util.StringJoiner;

/**
 * Builds the JA4T (TCP client) fingerprint from values observed in a TCP SYN
 * packet.
 *
 * <p>Format (per the FoxIO reference implementation):
 *
 * <pre>
 *   &lt;windowSize&gt;_&lt;tcpOptions&gt;_&lt;mss&gt;_&lt;windowScale&gt;
 * </pre>
 *
 * <ul>
 *   <li>{@code windowSize} – TCP window size value from the SYN (decimal).</li>
 *   <li>{@code tcpOptions} – TCP option kinds in the exact order observed,
 *       joined with {@code -}. When no options are present this is {@code 00}.</li>
 *   <li>{@code mss} – Maximum Segment Size option value, zero-padded to at least
 *       two digits ({@code 0} renders as {@code 00}).</li>
 *   <li>{@code windowScale} – Window Scale option shift; {@code 0}/absent renders
 *       as {@code 00}, any other value as a plain decimal.</li>
 * </ul>
 *
 * <p>Example: {@code 65535_2-4-8-1-3_1460_9}.
 */
public final class Ja4TcpFingerprint {

  private Ja4TcpFingerprint() {
  }

  /**
   * Computes the JA4T fingerprint.
   *
   * @param windowSize TCP window size value from the SYN.
   * @param optionKinds TCP option kind numbers in observed order (may be empty);
   *        includes repeated NOPs (1) and EOL (0) exactly as seen.
   * @param mss MSS option value, or 0 if the option was absent.
   * @param windowScale Window Scale shift value, or 0 if the option was absent.
   * @return the JA4T string, never {@code null}.
   */
  public static String compute(int windowSize, int[] optionKinds, int mss, int windowScale) {
    String options;
    if (optionKinds == null || optionKinds.length == 0) {
      options = "00";
    } else {
      StringJoiner joiner = new StringJoiner("-");
      for (int kind : optionKinds) {
        joiner.add(Integer.toString(kind));
      }
      options = joiner.toString();
    }
    String scale = windowScale == 0 ? "00" : Integer.toString(windowScale);
    return windowSize + "_" + options + "_" + String.format("%02d", mss) + "_" + scale;
  }
}
