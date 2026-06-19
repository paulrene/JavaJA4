package no.hux.ja4.capture;

import java.io.EOFException;
import java.net.InetAddress;
import java.sql.Timestamp;
import java.util.List;
import java.util.concurrent.TimeoutException;
import java.util.logging.Level;
import java.util.logging.Logger;
import no.hux.ja4.fingerprint.Ja4TcpFingerprint;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Packet.IpV4Header;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpMaximumSegmentSizeOption;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.TcpPacket.TcpHeader;
import org.pcap4j.packet.TcpPacket.TcpOption;
import org.pcap4j.packet.TcpWindowScaleOption;

/**
 * Out-of-band TCP handshake sniffer that derives JA4T (and real JA4L timing)
 * from the SYN / SYN-ACK / ACK packets of connections to the server port.
 *
 * <p>This component is optional. When a capture device cannot be opened (for
 * example, missing privileges or no libpcap), it logs a warning and stays
 * inactive so the server keeps serving fingerprints without JA4T/real-JA4L.
 *
 * <p>Captured data is keyed by the client {@code ip:port} in a {@link TcpInfoStore},
 * which the request handler joins against using the Netty channel's remote
 * address.
 */
public final class PacketCaptureService {

  private static final int DEFAULT_SNAPLEN = 256;
  private static final int DEFAULT_TIMEOUT_MS = 50;

  private final int serverPort;
  private final TcpInfoStore store;
  private final Logger logger;
  private final String configuredIface;
  private final InetAddress bindAddress;
  private final int snaplen;
  private final int timeoutMs;

  private volatile boolean running;
  private volatile PcapHandle handle;
  private Thread captureThread;

  public PacketCaptureService(int serverPort, InetAddress bindAddress, String configuredIface,
      TcpInfoStore store, Logger logger) {
    this(serverPort, bindAddress, configuredIface, DEFAULT_SNAPLEN, DEFAULT_TIMEOUT_MS, store,
        logger);
  }

  public PacketCaptureService(int serverPort, InetAddress bindAddress, String configuredIface,
      int snaplen, int timeoutMs, TcpInfoStore store, Logger logger) {
    this.serverPort = serverPort;
    this.bindAddress = bindAddress;
    this.configuredIface = configuredIface;
    this.snaplen = snaplen;
    this.timeoutMs = timeoutMs;
    this.store = store;
    this.logger = logger;
  }

  /**
   * Attempts to open a capture device and start the capture thread. Failures are
   * logged and leave the service inactive; they never propagate.
   *
   * @return {@code true} if capture started, {@code false} if it could not.
   */
  public boolean start() {
    try {
      PcapNetworkInterface nif = selectDevice();
      if (nif == null) {
        logger.warning("Packet capture disabled: no suitable capture device found");
        return false;
      }
      PcapHandle opened = nif.openLive(snaplen, PromiscuousMode.NONPROMISCUOUS, timeoutMs);
      opened.setFilter("tcp port " + serverPort, BpfCompileMode.OPTIMIZE);
      this.handle = opened;
      this.running = true;
      this.captureThread = new Thread(this::captureLoop, "ja4-capture");
      this.captureThread.setDaemon(true);
      this.captureThread.start();
      logger.log(Level.INFO, "Packet capture started on {0} (tcp port {1})",
          new Object[] {nif.getName(), serverPort});
      return true;
    } catch (PcapNativeException | NotOpenException | RuntimeException ex) {
      logger.log(Level.WARNING,
          "Packet capture disabled (could not open device; check privileges/libpcap)", ex);
      this.running = false;
      this.handle = null;
      return false;
    }
  }

  public void stop() {
    running = false;
    PcapHandle h = handle;
    if (h != null) {
      try {
        h.breakLoop();
      } catch (NotOpenException ignored) {
        // already closed
      }
      h.close();
    }
    if (captureThread != null) {
      captureThread.interrupt();
    }
  }

  private void captureLoop() {
    PcapHandle h = handle;
    while (running) {
      Packet packet;
      try {
        packet = h.getNextPacketEx();
      } catch (TimeoutException ex) {
        continue;
      } catch (EOFException | NotOpenException ex) {
        break;
      } catch (PcapNativeException ex) {
        logger.log(Level.FINE, "Packet capture read error", ex);
        continue;
      }
      try {
        handlePacket(packet, toEpochMicros(h.getTimestamp()));
      } catch (Exception ex) {
        logger.log(Level.FINE, "Failed to process captured packet", ex);
      }
    }
  }

  void handlePacket(Packet packet, long micros) {
    IpV4Packet ip = packet.get(IpV4Packet.class);
    if (ip == null) {
      // IPv6 (or non-IPv4) is not handled; the server itself binds IPv4 only.
      return;
    }
    TcpPacket tcp = packet.get(TcpPacket.class);
    if (tcp == null) {
      return;
    }
    IpV4Header iph = ip.getHeader();
    TcpHeader th = tcp.getHeader();
    int srcPort = th.getSrcPort().value() & 0xFFFF;
    int dstPort = th.getDstPort().value() & 0xFFFF;
    boolean syn = th.getSyn();
    boolean ack = th.getAck();

    if (dstPort == serverPort) {
      String clientIp = iph.getSrcAddr().getHostAddress();
      if (syn && !ack) {
        TcpHandshakeInfo info = store.getOrCreate(clientIp, srcPort);
        info.setSynMicros(micros);
        info.setClientTtl(iph.getTtlAsInt());
        info.setJa4t(buildJa4t(th));
      } else if (ack && !syn) {
        TcpHandshakeInfo info = store.get(clientIp, srcPort);
        if (info != null && info.getAckMicros() == 0L && info.getSynAckMicros() != 0L) {
          info.setAckMicros(micros);
        }
      }
    } else if (srcPort == serverPort && syn && ack) {
      String clientIp = iph.getDstAddr().getHostAddress();
      TcpHandshakeInfo info = store.get(clientIp, dstPort);
      if (info != null && info.getSynAckMicros() == 0L) {
        info.setSynAckMicros(micros);
      }
    }
  }

  static String buildJa4t(TcpHeader th) {
    List<TcpOption> options = th.getOptions();
    int[] kinds = new int[options.size()];
    int mss = 0;
    int windowScale = 0;
    for (int i = 0; i < options.size(); i++) {
      TcpOption option = options.get(i);
      kinds[i] = option.getKind().value() & 0xFF;
      if (option instanceof TcpMaximumSegmentSizeOption mssOption) {
        mss = mssOption.getMaxSegSizeAsInt();
      } else if (option instanceof TcpWindowScaleOption wscaleOption) {
        windowScale = wscaleOption.getShiftCountAsInt();
      }
    }
    return Ja4TcpFingerprint.compute(th.getWindowAsInt(), kinds, mss, windowScale);
  }

  static long toEpochMicros(Timestamp ts) {
    if (ts == null) {
      return 0L;
    }
    long epochSeconds = ts.getTime() / 1000L;
    return epochSeconds * 1_000_000L + ts.getNanos() / 1000L;
  }

  private PcapNetworkInterface selectDevice() throws PcapNativeException {
    if (configuredIface != null && !configuredIface.isBlank()) {
      PcapNetworkInterface nif = Pcaps.getDevByName(configuredIface);
      if (nif == null) {
        logger.log(Level.WARNING, "Configured capture interface not found: {0}", configuredIface);
      }
      return nif;
    }
    if (bindAddress != null && !bindAddress.isAnyLocalAddress()) {
      if (bindAddress.isLoopbackAddress()) {
        PcapNetworkInterface loopback = firstLoopback();
        if (loopback != null) {
          return loopback;
        }
      } else {
        PcapNetworkInterface byAddr = Pcaps.getDevByAddress(bindAddress);
        if (byAddr != null) {
          return byAddr;
        }
      }
    }
    return firstRunningNonLoopback();
  }

  private PcapNetworkInterface firstLoopback() throws PcapNativeException {
    for (PcapNetworkInterface nif : Pcaps.findAllDevs()) {
      if (nif.isLoopBack()) {
        return nif;
      }
    }
    return null;
  }

  private PcapNetworkInterface firstRunningNonLoopback() throws PcapNativeException {
    for (PcapNetworkInterface nif : Pcaps.findAllDevs()) {
      if (!nif.isLoopBack() && nif.isUp() && !nif.getAddresses().isEmpty()) {
        return nif;
      }
    }
    return null;
  }
}
