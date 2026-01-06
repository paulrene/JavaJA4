package no.hux.ja4.server;

import io.netty.buffer.ByteBuf;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import no.hux.ja4.fingerprint.Ja4Utils;

public final class ClientHelloParser {

  private ClientHelloParser() {
  }

  public static ClientHelloInfo tryParse(ByteBuf buffer) {
    int start = buffer.readerIndex();
    int end = start + buffer.readableBytes();
    int offset = start;

    while (end - offset >= 5) {
      int contentType = buffer.getUnsignedByte(offset);
      int recordLength = buffer.getUnsignedShort(offset + 3);
      int recordEnd = offset + 5 + recordLength;
      if (recordEnd > end) {
        return null;
      }
      if (contentType != 22) {
        offset = recordEnd;
        continue;
      }
      if (recordLength < 4 || recordEnd - offset < 9) {
        return null;
      }
      int handshakeType = buffer.getUnsignedByte(offset + 5);
      int handshakeLength = readUint24(buffer, offset + 6);
      int handshakeStart = offset + 9;
      int handshakeEnd = handshakeStart + handshakeLength;
      if (handshakeEnd > end) {
        return null;
      }
      if (handshakeType != 1) {
        offset = recordEnd;
        continue;
      }
      return parseClientHello(buffer, handshakeStart, handshakeEnd);
    }
    return null;
  }

  private static ClientHelloInfo parseClientHello(ByteBuf buffer, int offset, int end) {
    int index = offset;
    if (index + 34 > end) {
      return null;
    }

    int legacyVersion = buffer.getUnsignedShort(index);
    index += 2;
    index += 32;

    if (index + 1 > end) {
      return null;
    }
    int sessionIdLen = buffer.getUnsignedByte(index);
    index += 1;
    if (index + sessionIdLen > end) {
      return null;
    }
    index += sessionIdLen;

    if (index + 2 > end) {
      return null;
    }
    int cipherLen = buffer.getUnsignedShort(index);
    index += 2;
    if (index + cipherLen > end) {
      return null;
    }
    List<String> ciphers = new ArrayList<>();
    for (int i = 0; i + 1 < cipherLen; i += 2) {
      int cipher = buffer.getUnsignedShort(index + i);
      ciphers.add(Ja4Utils.hex(cipher));
    }
    index += cipherLen;

    if (index + 1 > end) {
      return null;
    }
    int compressionLen = buffer.getUnsignedByte(index);
    index += 1 + compressionLen;
    if (index > end) {
      return null;
    }

    List<String> extensions = new ArrayList<>();
    List<String> supportedVersions = new ArrayList<>();
    List<String> signatureAlgorithms = new ArrayList<>();
    List<String> alpnProtocols = new ArrayList<>();
    String serverName = null;

    if (index == end) {
      return new ClientHelloInfo(legacyVersion, ciphers, extensions, supportedVersions,
          signatureAlgorithms, alpnProtocols, serverName);
    }

    if (index + 2 > end) {
      return null;
    }
    int extensionsLen = buffer.getUnsignedShort(index);
    index += 2;
    int extensionsEnd = index + extensionsLen;
    if (extensionsEnd > end) {
      return null;
    }

    while (index + 4 <= extensionsEnd) {
      int extType = buffer.getUnsignedShort(index);
      int extLen = buffer.getUnsignedShort(index + 2);
      index += 4;
      if (index + extLen > extensionsEnd) {
        break;
      }
      extensions.add(Ja4Utils.hex(extType));
      if (extType == 0x0000) {
        serverName = parseServerName(buffer, index, extLen);
      } else if (extType == 0x0010) {
        parseAlpn(buffer, index, extLen, alpnProtocols);
      } else if (extType == 0x002b) {
        parseSupportedVersions(buffer, index, extLen, supportedVersions);
      } else if (extType == 0x000d) {
        parseSignatureAlgorithms(buffer, index, extLen, signatureAlgorithms);
      }
      index += extLen;
    }

    return new ClientHelloInfo(legacyVersion, ciphers, extensions, supportedVersions,
        signatureAlgorithms, alpnProtocols, serverName);
  }

  private static void parseSupportedVersions(ByteBuf buffer, int offset, int length,
      List<String> versions) {
    if (length < 1) {
      return;
    }
    int listLen = buffer.getUnsignedByte(offset);
    int index = offset + 1;
    int end = Math.min(offset + 1 + listLen, offset + length);
    while (index + 1 < end) {
      int version = buffer.getUnsignedShort(index);
      versions.add(Ja4Utils.hex(version));
      index += 2;
    }
  }

  private static void parseSignatureAlgorithms(ByteBuf buffer, int offset, int length,
      List<String> algorithms) {
    if (length < 2) {
      return;
    }
    int listLen = buffer.getUnsignedShort(offset);
    int index = offset + 2;
    int end = Math.min(offset + 2 + listLen, offset + length);
    while (index + 1 < end) {
      int alg = buffer.getUnsignedShort(index);
      algorithms.add(Ja4Utils.hex(alg));
      index += 2;
    }
  }

  private static void parseAlpn(ByteBuf buffer, int offset, int length,
      List<String> alpnProtocols) {
    if (length < 2) {
      return;
    }
    int listLen = buffer.getUnsignedShort(offset);
    int index = offset + 2;
    int end = Math.min(offset + 2 + listLen, offset + length);
    while (index < end) {
      int nameLen = buffer.getUnsignedByte(index);
      index += 1;
      if (index + nameLen > end) {
        break;
      }
      byte[] protocol = new byte[nameLen];
      buffer.getBytes(index, protocol);
      alpnProtocols.add(new String(protocol, StandardCharsets.US_ASCII));
      index += nameLen;
      if (!alpnProtocols.isEmpty()) {
        return;
      }
    }
  }

  private static String parseServerName(ByteBuf buffer, int offset, int length) {
    if (length < 2) {
      return null;
    }
    int listLen = buffer.getUnsignedShort(offset);
    int index = offset + 2;
    int end = Math.min(offset + 2 + listLen, offset + length);
    while (index + 3 <= end) {
      int nameType = buffer.getUnsignedByte(index);
      int nameLen = buffer.getUnsignedShort(index + 1);
      index += 3;
      if (index + nameLen > end) {
        break;
      }
      if (nameType == 0) {
        byte[] name = new byte[nameLen];
        buffer.getBytes(index, name);
        return new String(name, StandardCharsets.US_ASCII);
      }
      index += nameLen;
    }
    return null;
  }

  private static int readUint24(ByteBuf buffer, int offset) {
    return (buffer.getUnsignedByte(offset) << 16) | (buffer.getUnsignedByte(offset + 1) << 8)
        | buffer.getUnsignedByte(offset + 2);
  }
}
