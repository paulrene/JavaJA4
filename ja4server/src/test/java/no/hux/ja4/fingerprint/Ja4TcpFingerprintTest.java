package no.hux.ja4.fingerprint;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class Ja4TcpFingerprintTest {

  @Test
  void linuxStyleSynWithWindowScale() {
    // AWS Linux 2 example: 62727_2-4-8-1-3_8961_7
    String ja4t = Ja4TcpFingerprint.compute(62727, new int[] {2, 4, 8, 1, 3}, 8961, 7);
    assertEquals("62727_2-4-8-1-3_8961_7", ja4t);
  }

  @Test
  void windows10StyleSyn() {
    // Windows 10 example: 64240_2-1-3-1-1-4_1460_8
    String ja4t = Ja4TcpFingerprint.compute(64240, new int[] {2, 1, 3, 1, 1, 4}, 1460, 8);
    assertEquals("64240_2-1-3-1-1-4_1460_8", ja4t);
  }

  @Test
  void zeroWindowScaleRendersAsDoubleZero() {
    // F5 Big IP example: 4380_2-4-8_1460_0  -> window scale 0 renders as "00"
    String ja4t = Ja4TcpFingerprint.compute(4380, new int[] {2, 4, 8}, 1460, 0);
    assertEquals("4380_2-4-8_1460_00", ja4t);
  }

  @Test
  void absentMssRendersAsDoubleZero() {
    String ja4t = Ja4TcpFingerprint.compute(8192, new int[] {2, 1, 3}, 0, 2);
    assertEquals("8192_2-1-3_00_2", ja4t);
  }

  @Test
  void noOptionsRendersAsDoubleZero() {
    String ja4t = Ja4TcpFingerprint.compute(65535, new int[] {}, 0, 0);
    assertEquals("65535_00_00_00", ja4t);
  }

  @Test
  void nullOptionsTreatedAsEmpty() {
    String ja4t = Ja4TcpFingerprint.compute(1024, null, 1460, 0);
    assertEquals("1024_00_1460_00", ja4t);
  }

  @Test
  void singleMssOption() {
    // HP ILO example: 5840_2_1460_00
    String ja4t = Ja4TcpFingerprint.compute(5840, new int[] {2}, 1460, 0);
    assertEquals("5840_2_1460_00", ja4t);
  }
}
