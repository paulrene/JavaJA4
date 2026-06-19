# JA4 Fingerprinting Server

Netty-based JA4 fingerprinting server (Java 21) that captures:

- JA4 TLS Client fingerprint
- JA4 HTTP fingerprint
- JA4L Latency fingerprints: JA4L-C (client) always, and JA4L-S (server) when packet capture is enabled (real handshake timing + TTL when packet capture is enabled, otherwise JA4L-C is an application-level approximation)
- JA4T TCP Client fingerprint (requires packet capture)

The service is intended to be called by a client (browser/app) to generate a fingerprint, then queried by backend systems using the lookup API.

## How It Works

1. A client makes an HTTPS request to `https://server/<SessionID>`.
2. The server derives:
   - JA4 from the TLS ClientHello.
   - JA4H from the HTTP request headers.
   - JA4L from connection-accept → first-request timing (or, when packet capture is enabled, from the real TCP handshake timing and the client SYN's IP TTL).
   - JA4T from the client's TCP SYN (only when packet capture is enabled).
3. The result is stored in memory keyed by `<SessionID>`.
4. The response to the fingerprint request is a **1x1 GIF** with no-cache headers, and the connection is closed (`Connection: close`) since the fingerprint endpoint is one-shot.
5. A backend can retrieve the stored data using `https://server/api/lookup/<SessionID>`.

### Packet capture (JA4T and real JA4L)

JA4T and a true JA4L measurement require fields that live in the TCP/IP headers
(SYN window size, MSS, window scale, option order, and IP TTL) plus the exact
SYN / SYN-ACK / ACK timestamps. Netty runs **above** the kernel TCP stack, so by
the time bytes reach a handler the handshake is finished and those headers are
gone. To recover them the server can run an **optional, out-of-band libpcap
capture** alongside Netty in the same JVM, correlated to each connection by the
client `ip:port`.

This is **disabled by default**. Enable it with `--enable-pcap true` (see
[Configuration](#configuration)). When disabled, the server runs as a plain
pure-Java jar with no elevated privileges, JA4T is omitted, and JA4L falls back
to the accept → first-request estimate. Capture failures never degrade the
existing JA4/JA4H/JA4L behavior.

## Endpoints

- `https://server/<SessionID>`
  - Generates fingerprints and stores them in memory.
  - **Response:** 1x1 GIF (`image/gif`) with no-cache headers.
- `https://server/api/lookup/<SessionID>`
  - Fetches stored fingerprint data.
  - **Response:** JSON.

### Lookup Response JSON

```json
{
  "sessionId": "abc123",
  "timestamp": "2025-01-01T12:34:56Z",
  "ip": "203.0.113.10",
  "userAgent": "Mozilla/5.0 ...",
  "fingerprints": {
    "ja4": "t13d1516h2_8daaf6152771_02713d6af862",
    "ja4h": "ge11nn07enus_bc8d2ed93139_000000000000_000000000000",
    "ja4l": "420_0",
    "ja4ls": "5000_64",
    "ja4t": "65535_2-4-8-1-3_1460_6"
  }
}
```

The `ja4t` and `ja4ls` fields are only present when packet capture is enabled and
the relevant handshake packets were observed; otherwise they are omitted (or
`null`). `ja4l` (JA4L-C) is always present, falling back to an application-level
estimate when capture is disabled.

## Reading the Fingerprints

JA4 fingerprints use the `a_b_c` format (three parts separated by `_`). This allows matching on just `a`, `b`, `c`, or combinations (for example, `a+c` to ignore the middle section).

### JA4 (TLS Client Fingerprint)

Format:

```
t<ver><sni><cipher_count><ext_count><alpn>_<cipher_hash>_<ext_hash>
```

- `t` indicates TLS (Netty server only emits TLS here).
- `<ver>` is the TLS version code (e.g., `13`, `12`, `11`, `10`, `s3`, `s2`).
- `<sni>` is `d` if SNI is present, `i` if not.
- `<cipher_count>` is the number of non-GREASE ciphers (00-99).
- `<ext_count>` is the number of non-GREASE extensions (00-99).
- `<alpn>` is the first ALPN (first and last char), or `00` if missing.
- `<cipher_hash>` is a SHA-256 hash (first 12 hex chars) of sorted cipher IDs.
- `<ext_hash>` is a SHA-256 hash (first 12 hex chars) of sorted extension IDs,
  with signature algorithms appended when present.

Example:

```
t13d1516h2_8daaf6152771_02713d6af862
```

### JA4H (HTTP Client Fingerprint)

Format:

```
<method><version><cookie><referer><header_count><lang>_<headers_hash>_<cookie_fields_hash>_<cookie_values_hash>
```

- `<method>`: first two letters of HTTP method (lowercase), e.g., `ge` for GET.
- `<version>`: `10`, `11`, or `20` for HTTP/1.0, 1.1, or 2.
- `<cookie>`: `c` if Cookie header is present, `n` otherwise.
- `<referer>`: `r` if Referer header is present, `n` otherwise.
- `<header_count>`: number of header names (excluding cookies and referer).
- `<lang>`: 4-char language hint from `Accept-Language` (e.g., `enus`).
- `<headers_hash>`: SHA-256 hash (first 12 hex chars) of header names.
- `<cookie_fields_hash>`: SHA-256 hash of cookie field names.
- `<cookie_values_hash>`: SHA-256 hash of cookie values.

Example:

```
ge11nn07enus_bc8d2ed93139_000000000000_000000000000
```

### JA4L (Latency Fingerprints: JA4L-C and JA4L-S)

JA4L is split into two values, matching the FoxIO reference:

- **`ja4l` (JA4L-C, client latency):** half of the client's round-trip,
  paired with the client's TTL.
- **`ja4ls` (JA4L-S, server latency):** half of the server's round-trip,
  paired with the server's TTL.

Both use the format:

```
<latency>_<ttl>
```

- `<latency>`: one-way latency estimate in microseconds (one half of the
  observed round-trip).
- `<ttl>`: IP TTL of the relevant packet. Comparing the TTL to the nearest
  natural start value (64/128/255) yields a hop count.

How each is computed:

- **JA4L-C, real measurement (packet capture enabled):** `<latency>` is
  `(clientACK_time − serverSYNACK_time) / 2` from the observed TCP handshake, and
  `<ttl>` is the IP TTL of the client's SYN.
- **JA4L-C, estimate (packet capture disabled, or SYN not observed):**
  `<latency>` is half of the elapsed microseconds between connection accept and
  the first HTTP request, and `<ttl>` is `0`. This is a coarse application-level
  approximation, not a true JA4L.
- **JA4L-S (packet capture only):** `<latency>` is
  `(serverSYNACK_time − clientSYN_time) / 2` from the observed TCP handshake, and
  `<ttl>` is the IP TTL of the server's SYN/ACK. There is no application-level
  fallback, so `ja4ls` is omitted when capture is disabled or the handshake was
  not fully observed.

Examples:

```
ja4l:  420_0
ja4ls: 5000_64
```

### JA4T (TCP Client Fingerprint)

Derived from the client's TCP SYN; **only emitted when packet capture is
enabled** (see [Packet capture](#packet-capture-ja4t-and-real-ja4l)).

Format:

```
<windowSize>_<tcpOptionsInOrder>_<MSS>_<windowScale>
```

- `<windowSize>`: TCP window size from the SYN.
- `<tcpOptionsInOrder>`: TCP option kind numbers, dash-separated, in the exact
  order seen (e.g. `2`=MSS, `1`=NOP, `3`=Window Scale, `4`=SACK-permitted,
  `8`=Timestamp, `0`=EOL); `00` if there are no options.
- `<MSS>`: value from the MSS option (`00` if absent).
- `<windowScale>`: value from the Window Scale option (`00` if absent).

Example:

```
65535_2-4-8-1-3_1460_6
```

## Build

```sh
mvn -q -DskipTests package
```

The shaded executable is at `target/ja4-server.jar`.

## Run (local)

Generate a self-signed certificate using Netty PKI testing utilities:

```sh
./scripts/init-local-certs.sh --host localhost --ip 127.0.0.1
```

This creates:

- `certs/local/server.pem`
- `certs/local/server.key`
- `certs/local/ca.pem`

Start the server:

```sh
./scripts/start.sh --env local --port 8443
```

Example request flow:

```sh
curl -k https://localhost:8443/test-session -o /dev/null -s -w "%{http_code}\n"
curl -k https://localhost:8443/api/lookup/test-session
```

### Embedding in Web Pages

Use an image tag or fetch call from the client to generate the fingerprint:

```html
<img src="https://your-server.example.com/SESSION-ID" width="1" height="1" alt="" />
```

## Run (production with Let's Encrypt)

Request a certificate:

```sh
./scripts/init-letsencrypt.sh example.com admin@example.com
```

Start the server (reads from `/etc/letsencrypt/live/<domain>`):

```sh
./scripts/start.sh --env prod --domain example.com --port 443
```

Rotate certificates and restart:

```sh
./scripts/rotate-certs.sh
```

## Configuration

Command-line options:

```txt
--host <host>                 IPv4 bind address or hostname (default: 0.0.0.0)
--port <port>                 HTTPS port (default: 8443)
--env <local|prod>            Environment (default: local)
--cert <path>                 PEM certificate path
--key <path>                  PEM private key path
--domain <domain>             Domain for Let's Encrypt (prod mode)
--lets-encrypt-dir <path>     Let's Encrypt base dir (default: /etc/letsencrypt/live)
--ttl-seconds <seconds>       In-memory TTL (default: 86400)
--max-content-length <bytes>  Max HTTP body (default: 1048576)
--max-store-entries <count>   Max fingerprint records kept in memory (default: 100000)
--require-uuid-session-id <bool>  Reject session IDs that are not valid UUIDs (default: false)
--idle-timeout-seconds <seconds>  Close idle connections after N seconds, 0 disables (default: 60)
--enable-pcap <bool>          Enable out-of-band libpcap capture for JA4T and real JA4L (default: false)
--capture-iface <name>        Capture interface name (default: auto-selected from the bind address)
```

### Packet Capture Configuration

`--enable-pcap true` turns on the libpcap capture layer described in
[Packet capture](#packet-capture-ja4t-and-real-ja4l). This requires:

- **Native libpcap** present on the host:
  - macOS: bundled with the OS.
  - Linux: install `libpcap` (e.g. `apt-get install libpcap0.8`).
  - Windows: install [Npcap](https://npcap.com/).
- **Raw-packet privileges** for the JVM:
  - Run as root, **or**
  - Linux: grant capabilities once with
    `sudo setcap cap_net_raw,cap_net_admin+eip "$(readlink -f "$(command -v java)")"`
    (note: applies to the resolved `java` binary).

By default the capture interface is auto-selected from the bind address
(loopback when bound to `127.0.0.1`, otherwise the NIC owning the bind address,
falling back to the first running non-loopback device). Override it with
`--capture-iface` (e.g. `--capture-iface lo0` on macOS, `--capture-iface eth0`
on Linux).

If capture cannot start (missing privileges, no libpcap, no device), the server
logs a warning and continues without JA4T/real-JA4L — it never fails to start.

Example:

```sh
./scripts/start.sh --env local --port 8443 --enable-pcap true --capture-iface lo0
```

### Linux Deployment (systemd)

`scripts/start.sh` passes all flags straight through, so on Linux you only swap
the interface name:

```sh
./scripts/start.sh --env prod --domain example.com --port 443 \
  --enable-pcap true --capture-iface eth0
```

For a long-running service, prefer a systemd unit. systemd can grant
`CAP_NET_RAW` to just this service via `AmbientCapabilities` — cleaner than
`setcap` on the shared `java` binary, and it lets the process bind `:443` and
capture packets without running as full root:

```ini
# /etc/systemd/system/ja4-server.service
[Unit]
Description=JA4 Fingerprinting Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ja4
Group=ja4
WorkingDirectory=/opt/ja4server
ExecStart=/usr/bin/java -Xmx512m -XX:+ExitOnOutOfMemoryError \
  -jar /opt/ja4server/ja4-server.jar \
  --env prod --domain example.com --port 443 \
  --enable-pcap true --capture-iface eth0
# Required for packet capture and binding to :443 as a non-root user:
AmbientCapabilities=CAP_NET_RAW CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_BIND_SERVICE
NoNewPrivileges=true
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```sh
sudo apt-get install libpcap0.8          # native libpcap (Debian/Ubuntu)
sudo useradd --system --no-create-home ja4
sudo systemctl daemon-reload
sudo systemctl enable --now ja4-server
journalctl -u ja4-server -f              # follow logs
```

Notes:

- Drop `CAP_NET_BIND_SERVICE` if you terminate TLS behind a proxy and bind a
  high port (e.g. `--port 8443`).
- Drop both capabilities (and `--enable-pcap`) entirely to run the plain
  pure-Java server with no privileges.
- If the `ja4` user can't read the Let's Encrypt private key, either adjust the
  key's group/permissions or run a cert-copy step on renewal.

### Notes on TLS Configuration

- Local testing uses a self-signed cert generated via `netty-pkitesting`.
- Production uses Let's Encrypt certificates issued by `certbot`.
- You can override cert paths with `--cert` and `--key` if you manage TLS elsewhere.

## Operational Scripts

- `scripts/init-local-certs.sh`
  - Builds the jar (if needed) and generates local certs.
- `scripts/start.sh`
  - Starts the service in the background and writes a PID file.
  - Sets `JAVA_OPTS` to `-Xmx512m -XX:+ExitOnOutOfMemoryError -XX:+HeapDumpOnOutOfMemoryError -XX:HeapDumpPath=logs/` by default so the JVM fails fast with a heap dump on OOM. Override by exporting `JAVA_OPTS` before invoking the script.
- `scripts/stop.sh`
  - Stops the running service using the PID file.
- `scripts/rotate-certs.sh`
  - Runs `certbot renew` and restarts the service (if args were saved).
- `scripts/init-letsencrypt.sh`
  - Requests a new Let's Encrypt cert via `certbot`.

## Storage Behavior

- Fingerprints are stored in-memory keyed by SessionID.
- Data expires after `--ttl-seconds` (default: 24 hours).
- The store is capped at `--max-store-entries` records (default: 100 000); when full, the oldest entry is evicted on insert. Re-inserting an existing SessionID refreshes its position so frequently-seen sessions aren't evicted prematurely.
- When `--require-uuid-session-id true` is set, requests whose SessionID is not a canonical 8-4-4-4-12 hex UUID are rejected with `400`. Use this when your clients always provide UUIDs, to prevent scanner traffic from polluting the store.
- Lookups after expiry return `404`.
- The fingerprint endpoint closes the connection immediately after the GIF response (`Connection: close`), since each client fingerprints once and never reuses the socket. This frees the connection and its per-connection state right away rather than holding it until the idle timeout. The lookup API still honors keep-alive so backends can batch lookups.
- Idle connections are closed after `--idle-timeout-seconds` of no read or write activity (default: 60, `0` disables). This reaps half-open connections and any keep-alive connections (e.g. lookup-API clients or scanners) left open so they can't accumulate and exhaust memory.

## Logging

The server uses `java.util.logging` and logs errors such as:

- TLS handshake failures
- ClientHello parsing failures
- Expired record cleanup
- Request handling errors

Logs are written to `logs/ja4-server.log` when using `scripts/start.sh`.

## Limitations

- Without `--enable-pcap`, JA4L is computed from connection accept → first HTTP request timing and does not use IP TTL data (TTL is reported as `0`), and JA4T is not available.
- Packet capture (`--enable-pcap`) requires native libpcap/Npcap and raw-packet privileges (root or `CAP_NET_RAW`), changing the deployment model from a plain jar to one that needs capabilities and a native library.
- Behind an L4/L7 proxy, load balancer, or CDN, the SYN observed is the terminator's, not the real client's — so JA4T and the captured JA4L then describe the proxy, not the end client. (Same caveat FoxIO documents.)
- Capture only handles IPv4; the server itself binds IPv4 only.
- JA4 depends on parsing the TLS ClientHello bytes observed by Netty; unusual TLS implementations may be incomplete.
- Fingerprints are not persisted; use an external store if persistence is required.
- The server only binds to IPv4; use an IPv4 literal or a hostname that resolves to IPv4.

## References

- https://github.com/FoxIO-LLC/ja4
