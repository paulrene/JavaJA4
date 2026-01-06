# JA4 Fingerprinting Server

Netty-based JA4 fingerprinting server (Java 21) that captures:

- JA4 TLS Client fingerprint
- JA4 HTTP fingerprint
- JA4 Client Latency fingerprint (application-level approximation)

The service is intended to be called by a client (browser/app) to generate a fingerprint, then queried by backend systems using the lookup API.

## How It Works

1. A client makes an HTTPS request to `https://server/<SessionID>`.
2. The server derives:
   - JA4 from the TLS ClientHello.
   - JA4H from the HTTP request headers.
   - JA4L from connection-accept → first-request timing.
3. The result is stored in memory keyed by `<SessionID>`.
4. The response to the fingerprint request is a **1x1 GIF** with no-cache headers.
5. A backend can retrieve the stored data using `https://server/api/lookup/<SessionID>`.

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
    "ja4l": "420_0"
  }
}
```

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

### JA4L (Client Latency Fingerprint)

Format:

```
<latency>_<ttl>
```

- `<latency>`: half of the elapsed microseconds between connection accept and first HTTP request.
- `<ttl>`: TTL hint (this implementation uses `0`).

Example:

```
420_0
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
```

### Notes on TLS Configuration

- Local testing uses a self-signed cert generated via `netty-pkitesting`.
- Production uses Let's Encrypt certificates issued by `certbot`.
- You can override cert paths with `--cert` and `--key` if you manage TLS elsewhere.

## Operational Scripts

- `scripts/init-local-certs.sh`
  - Builds the jar (if needed) and generates local certs.
- `scripts/start.sh`
  - Starts the service in the background and writes a PID file.
- `scripts/stop.sh`
  - Stops the running service using the PID file.
- `scripts/rotate-certs.sh`
  - Runs `certbot renew` and restarts the service (if args were saved).
- `scripts/init-letsencrypt.sh`
  - Requests a new Let's Encrypt cert via `certbot`.

## Storage Behavior

- Fingerprints are stored in-memory keyed by SessionID.
- Data expires after `--ttl-seconds` (default: 24 hours).
- Lookups after expiry return `404`.

## Logging

The server uses `java.util.logging` and logs errors such as:

- TLS handshake failures
- ClientHello parsing failures
- Expired record cleanup
- Request handling errors

Logs are written to `logs/ja4-server.log` when using `scripts/start.sh`.

## Limitations

- JA4L is computed from connection accept → first HTTP request timing and does not use IP TTL data.
- JA4 depends on parsing the TLS ClientHello bytes observed by Netty; unusual TLS implementations may be incomplete.
- Fingerprints are not persisted; use an external store if persistence is required.
- The server only binds to IPv4; use an IPv4 literal or a hostname that resolves to IPv4.

## References

- https://github.com/FoxIO-LLC/ja4
