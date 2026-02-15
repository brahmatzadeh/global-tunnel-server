# Global Tunnel

Expose your local server to the internet with a public URL.

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

**Requirements:** Node.js 18+, sudo (Debian/Ubuntu).

When setup is done, the server runs as a **systemd service**: it starts automatically on boot and restarts if it crashes. You don’t need to run it manually.

To manage the service:

```bash
sudo systemctl status global-tunnel   # check status
sudo systemctl restart global-tunnel  # restart after config changes
sudo systemctl stop global-tunnel     # stop
sudo systemctl start global-tunnel    # start
```

To run the server manually (e.g. for debugging): `cd global-tunnel && npm run server`.

From any machine, run the client:

```bash
npx global-tunnel --port 3000 --server wss://tunnel.example.com
```

(Use the domain you entered during install.)

## License

MIT
