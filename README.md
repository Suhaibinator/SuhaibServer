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
