package no.hux.ja4.server;

import java.nio.file.Path;
import java.time.Duration;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

public final class ConfigParser {

  private ConfigParser() {
  }

  public static ServerConfig parse(String[] args) {
    Map<String, String> options = new HashMap<>();

    for (int i = 0; i < args.length; i++) {
      String arg = args[i];
      if ("--help".equals(arg) || "-h".equals(arg)) {
        throw new IllegalArgumentException("help");
      }
      if (arg.startsWith("--")) {
        String key;
        String value;
        int idx = arg.indexOf('=');
        if (idx > 2) {
          key = arg.substring(2, idx);
          value = arg.substring(idx + 1);
        } else {
          key = arg.substring(2);
          if (i + 1 < args.length && !args[i + 1].startsWith("--")) {
            value = args[++i];
          } else {
            value = "true";
          }
        }
        options.put(key.toLowerCase(Locale.ROOT), value);
      } else {
        throw new IllegalArgumentException("Unexpected argument: " + arg);
      }
    }

    String host = options.getOrDefault("host", "0.0.0.0");
    int port = parseInt(options.getOrDefault("port", "8443"), "port");
    String env = options.getOrDefault("env", "local");
    String domain = options.get("domain");
    Path letsEncryptDir = Path
        .of(options.getOrDefault("lets-encrypt-dir", "/etc/letsencrypt/live"));
    Path cert = options.containsKey("cert") ? Path.of(options.get("cert")) : null;
    Path key = options.containsKey("key") ? Path.of(options.get("key")) : null;
    Duration ttl = Duration
        .ofSeconds(parseLong(options.getOrDefault("ttl-seconds", "86400"), "ttl-seconds"));
    int maxContentLength = parseInt(options.getOrDefault("max-content-length", "1048576"),
        "max-content-length");
    String apiUserPassword = options.get("userpass");

    ServerConfig config = new ServerConfig(host, port, env, cert, key, letsEncryptDir, domain, ttl,
        maxContentLength, apiUserPassword);
    validate(config);
    return config;
  }

  public static void printUsage() {
    String usage = """
        Usage: java -jar ja4-server.jar [options]

        Options:
          --host <host>                   IPv4 bind address or hostname (default: 0.0.0.0)
          --port <port>                   HTTPS port (default: 8443)
          --userpass <username:password>  Add Basic Authentication protection of the /api/* endpoints
          --env <local|prod>              Environment (default: local)
          --cert <path>                   PEM certificate path
          --key <path>                    PEM private key path
          --domain <domain>               Domain for Let's Encrypt (prod mode)
          --lets-encrypt-dir <path>       Let's Encrypt base dir (default: /etc/letsencrypt/live)
          --ttl-seconds <seconds>         In-memory TTL (default: 86400)
          --max-content-length <bytes>    Max HTTP body (default: 1048576)
          --help                          Show this help
        """;
    System.out.println(usage);
  }

  private static int parseInt(String value, String name) {
    try {
      return Integer.parseInt(value);
    } catch (NumberFormatException ex) {
      throw new IllegalArgumentException("Invalid " + name + ": " + value);
    }
  }

  private static long parseLong(String value, String name) {
    try {
      return Long.parseLong(value);
    } catch (NumberFormatException ex) {
      throw new IllegalArgumentException("Invalid " + name + ": " + value);
    }
  }

  private static void validate(ServerConfig config) {
    if (config.getPort() < 1 || config.getPort() > 65535) {
      throw new IllegalArgumentException("Port must be between 1 and 65535");
    }
    if (config.isProd() && config.getCertPath() == null && config.getDomain() == null) {
      throw new IllegalArgumentException("Production mode requires --domain or --cert/--key");
    }
    if ((config.getCertPath() == null) != (config.getKeyPath() == null)) {
      throw new IllegalArgumentException("Both --cert and --key must be provided together");
    }
  }
}
