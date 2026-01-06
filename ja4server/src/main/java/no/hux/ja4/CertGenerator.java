package no.hux.ja4;

import io.netty.pkitesting.CertificateBuilder;
import io.netty.pkitesting.X509Bundle;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

public final class CertGenerator {

  private CertGenerator() {
  }

  public static void main(String[] args) {
    try {
      Options options = Options.parse(args);
      if (options.help) {
        Options.printUsage();
        return;
      }

      Files.createDirectories(options.outDir);
      Path certPath = options.outDir.resolve("server.pem");
      Path keyPath = options.outDir.resolve("server.key");
      Path caPath = options.outDir.resolve("ca.pem");

      if (!options.overwrite
          && (Files.exists(certPath) || Files.exists(keyPath) || Files.exists(caPath))) {
        throw new IllegalStateException(
            "Certificate files already exist. Use --overwrite to replace.");
      }

      CertificateBuilder caBuilder = new CertificateBuilder()
          .subject("CN=" + options.commonName + " Root CA").setIsCertificateAuthority(true)
          .notBefore(Instant.now().minus(1, ChronoUnit.DAYS))
          .notAfter(Instant.now().plus(options.days, ChronoUnit.DAYS));

      X509Bundle caBundle = caBuilder.buildSelfSigned();

      CertificateBuilder builder = new CertificateBuilder().subject("CN=" + options.commonName)
          .notBefore(Instant.now().minus(1, ChronoUnit.DAYS))
          .notAfter(Instant.now().plus(options.days, ChronoUnit.DAYS))
          .addExtendedKeyUsageServerAuth();

      for (String host : options.hosts) {
        builder.addSanDnsName(host);
      }
      for (String ip : options.ips) {
        builder.addSanIpAddress(ip);
      }

      X509Bundle bundle = builder.buildIssuedBy(caBundle);
      String chainPem = bundle.getCertificatePathPEM() + System.lineSeparator()
          + caBundle.getRootCertificatePEM();
      writeString(certPath, chainPem);
      writeString(keyPath, bundle.getPrivateKeyPEM());
      writeString(caPath, caBundle.getRootCertificatePEM());

      System.out.println("Wrote " + certPath + ", " + keyPath + ", and " + caPath);
    } catch (Exception ex) {
      System.err.println("Failed to generate certificate: " + ex.getMessage());
      System.exit(1);
    }
  }

  private static void writeString(Path path, String content) throws IOException {
    Files.writeString(path, content);
  }

  private static final class Options {
    private final Path outDir;
    private final List<String> hosts;
    private final List<String> ips;
    private final String commonName;
    private final int days;
    private final boolean overwrite;
    private final boolean help;

    private Options(Path outDir, List<String> hosts, List<String> ips, String commonName, int days,
        boolean overwrite, boolean help) {
      this.outDir = outDir;
      this.hosts = hosts;
      this.ips = ips;
      this.commonName = commonName;
      this.days = days;
      this.overwrite = overwrite;
      this.help = help;
    }

    static Options parse(String[] args) {
      Path outDir = Path.of("certs", "local");
      List<String> hosts = new ArrayList<>();
      List<String> ips = new ArrayList<>();
      String commonName = "localhost";
      int days = 365;
      boolean overwrite = false;
      boolean help = false;

      for (int i = 0; i < args.length; i++) {
        String arg = args[i];
        switch (arg) {
        case "--help", "-h" -> help = true;
        case "--out-dir" -> outDir = Path.of(nextValue(args, ++i, arg));
        case "--host" -> hosts.add(nextValue(args, ++i, arg));
        case "--ip" -> ips.add(nextValue(args, ++i, arg));
        case "--cn" -> commonName = nextValue(args, ++i, arg);
        case "--days" -> days = Integer.parseInt(nextValue(args, ++i, arg));
        case "--overwrite" -> overwrite = true;
        default -> throw new IllegalArgumentException("Unknown option: " + arg);
        }
      }

      if (hosts.isEmpty()) {
        hosts.add(commonName);
      }
      if (ips.isEmpty()) {
        ips.add("127.0.0.1");
      }

      return new Options(outDir, hosts, ips, commonName, days, overwrite, help);
    }

    static void printUsage() {
      String usage = """
          Usage: java -cp ja4-server.jar no.hux.ja4.CertGenerator [options]

          Options:
            --out-dir <path>   Output directory (default: certs/local)
            --host <dns>       DNS SAN entry (repeatable)
            --ip <ip>          IP SAN entry (repeatable)
            --cn <name>        Common name (default: localhost)
            --days <days>      Validity in days (default: 365)
            --overwrite        Replace existing files
            --help             Show this help
          """;
      System.out.println(usage);
    }

    private static String nextValue(String[] args, int index, String arg) {
      if (index >= args.length) {
        throw new IllegalArgumentException("Missing value for " + arg);
      }
      return args[index];
    }
  }
}
