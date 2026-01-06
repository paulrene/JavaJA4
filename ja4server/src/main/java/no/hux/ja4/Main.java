package no.hux.ja4;

import java.util.logging.ConsoleHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import no.hux.ja4.server.ConfigParser;
import no.hux.ja4.server.Ja4Server;
import no.hux.ja4.server.ServerConfig;

public final class Main {
  private static final Logger LOGGER = Logger.getLogger(Main.class.getName());

  private Main() {
  }

  public static void main(String[] args) {
    ServerConfig config;
    try {
      config = ConfigParser.parse(args);
    } catch (IllegalArgumentException ex) {
      if ("help".equals(ex.getMessage())) {
        ConfigParser.printUsage();
        return;
      }
      System.err.println(ex.getMessage());
      ConfigParser.printUsage();
      System.exit(1);
      return;
    }

    configureLogging();

    try {
      Ja4Server server = new Ja4Server(config, LOGGER);
      server.start();
    } catch (Exception ex) {
      LOGGER.log(Level.SEVERE, "Server failed to start", ex);
      System.exit(2);
    }
  }

  private static void configureLogging() {
    Logger root = Logger.getLogger("");
    for (var handler : root.getHandlers()) {
      handler.setLevel(Level.INFO);
      if (handler instanceof ConsoleHandler consoleHandler) {
        consoleHandler.setLevel(Level.INFO);
      }
    }
    root.setLevel(Level.INFO);
  }
}
