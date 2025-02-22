# SuhaibServer

[![Build](https://github.com/Suhaibinator/SuhaibServer/actions/workflows/build.yaml/badge.svg)](https://github.com/Suhaibinator/SuhaibServer/actions/workflows/build.yaml)
[![Test](https://github.com/Suhaibinator/SuhaibServer/actions/workflows/test.yaml/badge.svg)](https://github.com/Suhaibinator/SuhaibServer/actions/workflows/test.yaml)
[![Publish](https://github.com/Suhaibinator/SuhaibServer/actions/workflows/publish.yaml/badge.svg)](https://github.com/Suhaibinator/SuhaibServer/actions/workflows/publish.yaml)

**SuhaibServer** is a reverse proxy designed to simplify and enhance TLS and mTLS (Mutual TLS) management beyond what is typically possible in solutions like NGINX or Apache. By leveraging **SNI (Server Name Indication)**, SuhaibServer allows you to define highly granular routing and security policies per domain—right down to specific URLs and query parameters.

---

## Key Features

### Advanced SNI Routing
- **Route incoming connections** based on SNI immediately.  
- **Simplify your configuration** by grouping all TLS/mTLS rules according to the hostname.

### Flexible TLS & mTLS Options
- **TCP Pass-Through**: Let the origin server handle TLS/mTLS completely.  
- **TLS Termination**: Terminate TLS at SuhaibServer, and pass requests on to the origin via HTTP or HTTPS.  
- **Granular mTLS**: Enforce mTLS on a per-path or per-query-parameter basis, or allow requests through without client certificates.

### Customizable Certificate Validation
- **Configure different root CAs** for each hostname or route.  
- **Control certificate validation** behavior for one service without affecting another.

### High-Granularity Policy Management
- **Easily combine criteria** such as routes, query parameters, SNI, and more.  
- **Use logical conditions** to decide whether to perform mTLS validation or simply forward traffic.

### Origin Server Flexibility
- **Explicitly define origin servers** for each route.  
- **Combine SuhaibServer’s advanced SNI logic** with your existing setups for maximum compatibility.

---

## Why SuhaibServer?
- **Fine-Grained mTLS Control**: Most reverse proxies only allow mTLS to be toggled on or off globally or at best at the server block level. SuhaibServer’s per-route customization puts you in full control.  
- **SNI-First Logic**: Routing is decided purely on the SNI before any additional overhead—perfect for multi-tenant or complex architectures.  
- **Clear, Modular Configuration**: Each domain or path can have a dedicated set of TLS rules, making your configuration easier to maintain and reason about.  
- **Seamless Integration**: Insert SuhaibServer into your stack without disrupting existing workflows, whether you need pass-through or termination for TLS.

---

## Getting Started

### 1. Build From Source

1. **Clone** the repository:
   ```bash
   git clone https://github.com/Suhaibinator/SuhaibServer.git
   cd SuhaibServer
   ```
2. **Build** the binary:
   ```bash
   go build -o suhaibserver ./cmd/main.go
   ```
   (Requires Go 1.18+ or newer.)

3. **Run** the binary with a config file:
   ```bash
   ./suhaibserver /path/to/config.yaml
   ```

### 2. Docker Usage

We publish a Docker image that can be used directly, or you can build it yourself.

#### a) Pull and Run (Hypothetical Example)
```bash
docker pull suhaibinator/suhaibserver:latest
docker run -d \
  -p 443:443 \
  -v /host/certs/:/etc/certs/:ro \
  -v /host/config.yaml:/etc/suhaib/config.yaml:ro \
  suhaibinator/suhaibserver:latest \
  /etc/suhaib/config.yaml
```
- `-v /host/certs/:/etc/certs/:ro` makes certificates available to the container at `/etc/certs/`.
- `-v /host/config.yaml:/etc/suhaib/config.yaml:ro` mounts your config file inside the container.
- The last argument (`/etc/suhaib/config.yaml`) tells SuhaibServer which config file to load.

#### b) Building Your Own Docker Image
If you have cloned the repo, run:
```bash
docker build -t my-suhaibserver .
docker run -d \
  -p 443:443 \
  -v /host/certs/:/etc/certs/:ro \
  -v /host/config.yaml:/etc/suhaib/config.yaml:ro \
  my-suhaibserver:latest \
  /etc/suhaib/config.yaml
```

---

## Example Configuration

Below is an example YAML configuration (`config.example.yaml`). It shows how to:

1. Configure **SNI sniffing** (max read size and handshake timeout).
2. Define one or more **Backends** (one per hostname).
3. Control whether to **terminate TLS**, **enable mTLS**, or **pass-through** raw TCP.

```yaml
# SniSniffer controls how we read the initial bytes of an incoming TLS connection
# to detect the SNI.
SniSniffer:
  MaxReadSize: 4096
  Timeout: 5s

Backends:
  - hostname: example.com
    MTLSEnabled: true
    MTLSPolicy:
      # Default=false => do NOT require mTLS by default
      # But invert the default if the path starts with /admin or the query param "token" is present
      default: false
      paths:
        - /admin
      queries:
        - token
    TerminateTLS: true
    TLSCertFile: example.com.crt
    TLSKeyFile:  example.com.key
    RootCAFile:  ca.crt
    OriginServer: 127.0.0.1
    OriginPort: "8080"

  - hostname: foo.bar
    MTLSEnabled: false   # no mTLS for foo.bar
    TerminateTLS: false  # pass-through raw TCP
    OriginServer: 192.168.0.10
    OriginPort: "443"
```

### How Cert Paths Are Resolved
- If a path in the config is not absolute (e.g. `"example.com.crt"`), SuhaibServer can automatically prepend `/etc/certs/` internally (depending on your setup).  
- In Docker, you’d likely mount your certs into the container at `/etc/certs/`.

---

## Usage

```bash
suhaibserver <config-file>
```

- `<config-file>` can be YAML or JSON.  
- The config **must** define `SniSniffer` parameters and at least one `Backend`.  
- Each `Backend` includes:
  - `Hostname` - matches the SNI requested by the client.
  - `TerminateTLS` (true/false).
  - `MTLSEnabled` (true/false) and optional `MTLSPolicy` for partial or conditional mTLS.  
  - `TLSCertFile`, `TLSKeyFile`, `RootCAFile` (paths to certificates/keys).  
  - `OriginServer` and `OriginPort` (where traffic is forwarded).

---

## mTLS Policies

Use `MTLSEnabled: true` to enable partial or full mTLS. Then define `MTLSPolicy` to choose whether mTLS is the **default** or an **exception**:

- **`default: true`**: all paths/queries require a client cert unless they match the listed paths or queries (which become “no-mTLS” exceptions).  
- **`default: false`**: no paths/queries require a client cert unless they match the listed paths or queries (which become “require-mTLS” exceptions).

Examples:
```yaml
MTLSPolicy:
  default: false
  paths:
    - /admin     # routes starting with /admin require mTLS
  queries:
    - token      # any request containing ?token=... in the query string requires mTLS
```

---

## Contributing

1. **Fork** this repository and create a branch for your feature or bugfix.  
2. **Test** your changes with `go test ./...`.  
3. **Submit** a Pull Request and fill out the template.

---

## License

SuhaibServer is licensed under the [MIT License](LICENSE).  