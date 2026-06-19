package no.hux.ja4.capture;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import org.junit.jupiter.api.Test;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV4Rfc1349Tos;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpMaximumSegmentSizeOption;
import org.pcap4j.packet.TcpNoOperationOption;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.TcpPacket.TcpOption;
import org.pcap4j.packet.TcpWindowScaleOption;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.pcap4j.packet.namednumber.IpVersion;
import org.pcap4j.packet.namednumber.TcpPort;
import org.pcap4j.util.MacAddress;

class PacketCaptureServiceTest {

  private static final int SERVER_PORT = 8443;
  private static final int CLIENT_PORT = 51000;
  private static final String CLIENT_IP = "203.0.113.10";
  private static final String SERVER_IP = "198.51.100.5";

  private PacketCaptureService newService(TcpInfoStore store) {
    return new PacketCaptureService(SERVER_PORT, null, null, store, Logger.getLogger("test"));
  }

  @Test
  void clientSynProducesJa4tAndTtl() throws Exception {
    TcpInfoStore store = new TcpInfoStore(60L, 1000, Logger.getLogger("test"));
    PacketCaptureService service = newService(store);

    // options: MSS(1460), NOP, WindowScale(6) -> kinds 2-1-3 (8 bytes, 4-byte aligned)
    Packet syn = buildTcp(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT, true, false, 65535, 64,
        synOptions(1460, (byte) 6));
    service.handlePacket(syn, 1_000_000L);

    TcpHandshakeInfo info = store.get(CLIENT_IP, CLIENT_PORT);
    assertNotNull(info);
    assertEquals("65535_2-1-3_1460_6", info.getJa4t());
    assertEquals(64, info.getClientTtl());
  }

  @Test
  void fullHandshakeProducesRealJa4l() throws Exception {
    TcpInfoStore store = new TcpInfoStore(60L, 1000, Logger.getLogger("test"));
    PacketCaptureService service = newService(store);

    Packet syn = buildTcp(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT, true, false, 65535, 64,
        synOptions(1460, (byte) 6));
    Packet synAck = buildTcp(SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT, true, true, 65535, 64,
        synOptions(1460, (byte) 6));
    Packet ack = buildTcp(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT, false, true, 65535, 64,
        new ArrayList<>());

    service.handlePacket(syn, 1_000_000L);
    service.handlePacket(synAck, 1_010_000L);
    service.handlePacket(ack, 1_030_000L);

    TcpHandshakeInfo info = store.get(CLIENT_IP, CLIENT_PORT);
    assertNotNull(info);
    // JA4L-C = (ack - synAck) / 2 = (1_030_000 - 1_010_000) / 2 = 10_000 us; client ttl 64.
    assertEquals("10000_64", info.computeJa4lC());
    // JA4L-S = (synAck - syn) / 2 = (1_010_000 - 1_000_000) / 2 = 5_000 us; server ttl 64.
    assertEquals("5000_64", info.computeJa4lS());
  }

  @Test
  void unrelatedPortIsIgnored() throws Exception {
    TcpInfoStore store = new TcpInfoStore(60L, 1000, Logger.getLogger("test"));
    PacketCaptureService service = newService(store);

    Packet syn = buildTcp(CLIENT_IP, CLIENT_PORT, SERVER_IP, 1234, true, false, 65535, 64,
        synOptions(1460, (byte) 6));
    service.handlePacket(syn, 1_000_000L);

    assertNull(store.get(CLIENT_IP, CLIENT_PORT));
  }

  private static List<TcpOption> synOptions(int mss, byte windowScale) {
    // MSS (4) + NOP (1) + Window Scale (3) = 8 bytes, 4-byte aligned so the
    // header round-trips through raw bytes exactly like a real SYN.
    List<TcpOption> options = new ArrayList<>();
    options.add(new TcpMaximumSegmentSizeOption.Builder()
        .maxSegSize((short) mss).correctLengthAtBuild(true).build());
    options.add(TcpNoOperationOption.getInstance());
    options.add(new TcpWindowScaleOption.Builder()
        .shiftCount(windowScale).correctLengthAtBuild(true).build());
    return options;
  }

  private static Packet buildTcp(String srcIp, int srcPort, String dstIp, int dstPort,
      boolean syn, boolean ack, int window, int ttl, List<TcpOption> options) throws Exception {
    Inet4Address src = (Inet4Address) InetAddress.getByName(srcIp);
    Inet4Address dst = (Inet4Address) InetAddress.getByName(dstIp);

    TcpPacket.Builder tcp = new TcpPacket.Builder()
        .srcPort(TcpPort.getInstance((short) srcPort))
        .dstPort(TcpPort.getInstance((short) dstPort))
        .srcAddr(src)
        .dstAddr(dst)
        .sequenceNumber(1)
        .acknowledgmentNumber(ack ? 1 : 0)
        .syn(syn)
        .ack(ack)
        .window((short) window)
        .options(options)
        .correctChecksumAtBuild(true)
        .correctLengthAtBuild(true);

    IpV4Packet.Builder ip = new IpV4Packet.Builder()
        .version(IpVersion.IPV4)
        .tos(IpV4Rfc1349Tos.newInstance((byte) 0))
        .ttl((byte) ttl)
        .protocol(IpNumber.TCP)
        .srcAddr(src)
        .dstAddr(dst)
        .payloadBuilder(tcp)
        .correctChecksumAtBuild(true)
        .correctLengthAtBuild(true)
        .paddingAtBuild(true);

    EthernetPacket.Builder eth = new EthernetPacket.Builder()
        .srcAddr(MacAddress.getByName("00:00:00:00:00:01"))
        .dstAddr(MacAddress.getByName("00:00:00:00:00:02"))
        .type(EtherType.IPV4)
        .payloadBuilder(ip)
        .paddingAtBuild(true);

    // Round-trip through raw bytes to mirror exactly what libpcap delivers at
    // capture time. This exercises the pcap4j packet factory: if the factory
    // dependency is missing, dissection yields a null IpV4Packet and the
    // assertions below fail (guarding against silent capture breakage).
    byte[] raw = eth.build().getRawData();
    return EthernetPacket.newPacket(raw, 0, raw.length);
  }
}
