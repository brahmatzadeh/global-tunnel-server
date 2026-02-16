# Global Tunnel

Expose your local server to the internet with a public URL.

**Client:** [global-tunnel-client](https://github.com/brahmatzadeh/global-tunnel-client) — standalone client that exposes a local port through a public URL via this server.

## How to install the server

On the machine that will host the tunnel (e.g. a VPS), run:

```bash
git clone <this-repo>
cd global-tunnel
./install.sh
```

The script will ask for:

1. **Tunnel domain** — e.g. `tunnel.example.com` (URLs will be `https://<subdomain>.tunnel.example.com`).
2. **Backend port** — default `4040`.
3. **Public port** — default `443`.
4. **Protocol** — default `https`.

It then installs certbot and nginx if needed, guides you through DNS (wildcard A record) and a Let's Encrypt wildcard cert, configures nginx, and writes `.env`.

**Requirements:** Go 1.21+, sudo (Debian/Ubuntu).

When setup is done, start the server:

```bash
go run ./server
# or build and run:
go build -o global-tunnel-server ./server && ./global-tunnel-server
```

Use any tunnel client that connects to `wss://<your-domain>/_tunnel` and sends a `register` message (optional `subdomain`, `tcpPort`). The server responds with `registered` (subdomain, url, etc.).

## Preferred subdomain

Clients can request a specific subdomain when registering. If that subdomain is valid and not already in use, the server assigns it; otherwise it assigns a random one.

- **Request:** send `subdomain` in the register message, e.g. `{ "type": "register", "subdomain": "myapp" }`.
- **Rules:** 1–63 characters, lowercase letters, digits, and hyphens only (valid DNS label). The server normalizes (e.g. `MyApp` → `myapp`).
- **Response:** the `registered` message includes:
  - `subdomain` — the assigned subdomain (requested or random)
  - `url` — full tunnel URL
  - `requestedSubdomain` — what you asked for (if any)
  - `usedRequestedSubdomain` — `true` if you got your requested subdomain, `false` if it was taken or invalid

Clients send e.g. `{ "type": "register", "subdomain": "myapp" }` to request that subdomain.

## TCP tunnel

The server can proxy raw TCP in addition to HTTP. Useful for databases, SSH, or any TCP service.

### Enable on the server

Set **`TCP_TUNNEL_PORT`** in `.env` (e.g. `4000`). If unset or `0`, TCP tunneling is disabled.

```bash
# In .env or environment
TCP_TUNNEL_PORT=4000
```

Restart the server. It will listen on that port for TCP connections.

### How public clients connect

1. Open a TCP connection to the server on `TCP_TUNNEL_PORT` (e.g. `tunnel.example.com:4000`).
2. Send the **subdomain** as a single line ending with newline: `subdomain\n` (e.g. `myapp\n`).
3. After that, all bytes are forwarded to the tunnel client’s local TCP service (and back).

Example with `nc`:

```bash
( echo "myapp"; cat ) | nc tunnel.example.com 4000
```

### Client registration

When registering, the tunnel client can expose a local TCP port by sending **`tcpPort`** (1–65535):

```json
{ "type": "register", "subdomain": "myapp", "tcpPort": 5432 }
```

The server response includes **`tcpTunnelPort`** when TCP is enabled (e.g. `4000`), so users know which port to connect to. The client must handle `tcp-connect` messages: open a TCP connection to `localhost:tcpPort`, then send `tcp-connected` or `tcp-error`, and forward `tcp-data` / `tcp-close` in both directions over the WebSocket.

### Firewall

If you use a firewall, open `TCP_TUNNEL_PORT` (e.g. 4000) in addition to 80/443.

## License

MIT
