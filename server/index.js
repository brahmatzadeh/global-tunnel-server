#!/usr/bin/env node

/**
 * Tunnel Server
 * Accepts WebSocket connections from tunnel clients and forwards HTTP traffic
 * from the public internet to the appropriate client based on subdomain.
 * Optional TCP tunnel: public clients connect to TCP_TUNNEL_PORT, send "subdomain\n", then raw TCP is proxied to the client's local port.
 */

import "dotenv/config";
import http from "http";
import https from "https";
import fs from "fs";
import net from "net";
import { WebSocketServer } from "ws";
import { randomBytes } from "crypto";

const PORT = parseInt(process.env.PORT || "443", 10);
const TUNNEL_DOMAIN = process.env.TUNNEL_DOMAIN || "localhost";
// TCP tunnel: set TCP_TUNNEL_PORT (e.g. 4000) to enable. Public clients connect, send "subdomain\n", then raw TCP is forwarded.
const TCP_TUNNEL_PORT = parseInt(process.env.TCP_TUNNEL_PORT || "0", 10);

// When behind a reverse proxy (e.g. nginx on 443): app listens on PORT but public URL is on PUBLIC_PORT.
const PUBLIC_PORT = process.env.PUBLIC_PORT != null ? parseInt(process.env.PUBLIC_PORT, 10) : PORT;
const PUBLIC_PROTOCOL = process.env.PUBLIC_PROTOCOL || (PUBLIC_PORT === 443 ? "https" : PUBLIC_PORT === 80 ? "http" : "http");

// Optional TLS for HTTPS on 443 (set TLS_CERT_PATH and TLS_KEY_PATH, or TLS_CERT + TLS_KEY)
const TLS_CERT_PATH = process.env.TLS_CERT_PATH || process.env.TLS_CERT;
const TLS_KEY_PATH = process.env.TLS_KEY_PATH || process.env.TLS_KEY;
const useTls =
  PORT === 443 && TLS_CERT_PATH && TLS_KEY_PATH;

function loadTlsOptions() {
  if (!useTls) return null;
  try {
    return {
      cert: fs.readFileSync(TLS_CERT_PATH, "utf8"),
      key: fs.readFileSync(TLS_KEY_PATH, "utf8"),
    };
  } catch (e) {
    console.error("TLS cert/key load failed:", e.message);
    return null;
  }
}

const tlsOptions = loadTlsOptions();
const protocol = useTls && tlsOptions ? "https" : "http";
// Advertised URL uses public port/protocol (for reverse proxy); port suffix only if not 80/443
const portSuffix =
  PUBLIC_PORT === 80 || PUBLIC_PORT === 443 ? "" : ":" + PUBLIC_PORT;
const advertisedProtocol = PUBLIC_PROTOCOL;

// subdomain -> { ws, createdAt, tcpPort? }
const tunnels = new Map();
// requestId -> { resolve, reject, timeout }
const pendingRequests = new Map();
// proxied WebSocket id -> { browserWs, tunnelWs }
const pendingProxiedWs = new Map();
// tcp connection id -> { publicSocket, tunnelWs, buffer }
const pendingTcpConnections = new Map();

const REQUEST_TIMEOUT_MS = 60_000;
const TCP_CONNECT_TIMEOUT_MS = 15_000;
const TCP_HANDSHAKE_TIMEOUT_MS = 5_000;

function generateSubdomain() {
  return randomBytes(4).toString("hex");
}

// Subdomain must be a valid DNS label: 1–63 chars, lowercase alphanumeric and hyphen, no leading/trailing hyphen
const SUBDOMAIN_MAX_LEN = 63;
const SUBDOMAIN_REGEX = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;

function isValidSubdomain(s) {
  if (typeof s !== "string" || s.length === 0 || s.length > SUBDOMAIN_MAX_LEN) return false;
  return SUBDOMAIN_REGEX.test(s);
}

function normalizeSubdomain(s) {
  return String(s).toLowerCase().trim();
}

function extractSubdomain(host) {
  if (!host) return null;
  const hostname = host.split(":")[0];
  const parts = hostname.split(".");
  if (parts.length >= 2) {
    return parts[0];
  }
  if (hostname === "localhost" || hostname === "127.0.0.1") {
    return null;
  }
  return hostname;
}

function parseRequestBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", () => resolve(Buffer.alloc(0)));
  });
}

function createTcpTunnelServer() {
  const tcpServer = net.createServer((publicSocket) => {
    let handshakeDone = false;
    let buf = Buffer.alloc(0);
    const handshakeTimeout = setTimeout(() => {
      if (!handshakeDone) {
        handshakeDone = true;
        publicSocket.destroy();
      }
    }, TCP_HANDSHAKE_TIMEOUT_MS);

    function consumeHandshake() {
      const idx = buf.indexOf(0x0a); // '\n'
      if (idx === -1) return false;
      handshakeDone = true;
      clearTimeout(handshakeTimeout);
      const line = buf.subarray(0, idx).toString("utf8").trim();
      const rest = buf.subarray(idx + 1);
      buf = Buffer.alloc(0);
      const subdomain = normalizeSubdomain(line);
      if (!subdomain || !isValidSubdomain(subdomain)) {
        publicSocket.destroy();
        return;
      }
      const tunnel = tunnels.get(subdomain);
      if (!tunnel || tunnel.ws.readyState !== 1 || tunnel.tcpPort == null) {
        publicSocket.destroy();
        return;
      }
      const id = randomBytes(8).toString("hex");
      const entry = {
        publicSocket,
        tunnelWs: tunnel.ws,
        buffer: rest.length > 0 ? [rest] : [],
        connectTimeout: setTimeout(() => {
          if (pendingTcpConnections.has(id)) {
            pendingTcpConnections.delete(id);
            publicSocket.destroy();
          }
        }, TCP_CONNECT_TIMEOUT_MS),
      };
      pendingTcpConnections.set(id, entry);
      try {
        tunnel.ws.send(JSON.stringify({ type: "tcp-connect", id, port: tunnel.tcpPort }));
      } catch (err) {
        pendingTcpConnections.delete(id);
        clearTimeout(entry.connectTimeout);
        publicSocket.destroy();
        return;
      }
      publicSocket.removeAllListeners("data");
      publicSocket.on("data", (chunk) => {
        if (entry.connectTimeout != null) {
          entry.buffer.push(chunk);
        }
      });
      publicSocket.on("close", () => {
        if (pendingTcpConnections.has(id)) {
          pendingTcpConnections.delete(id);
          if (entry.connectTimeout) clearTimeout(entry.connectTimeout);
          if (tunnel.ws.readyState === 1) {
            tunnel.ws.send(JSON.stringify({ type: "tcp-close", id }));
          }
        }
      });
      publicSocket.on("error", () => {
        if (pendingTcpConnections.has(id)) {
          pendingTcpConnections.delete(id);
          if (entry.connectTimeout) clearTimeout(entry.connectTimeout);
          if (tunnel.ws.readyState === 1) {
            tunnel.ws.send(JSON.stringify({ type: "tcp-close", id }));
          }
        }
      });
    }

    publicSocket.on("data", (chunk) => {
      if (handshakeDone) return;
      buf = Buffer.concat([buf, chunk]);
      consumeHandshake();
    });
  });

  tcpServer.listen(TCP_TUNNEL_PORT, () => {
    console.log(`TCP tunnel listening on port ${TCP_TUNNEL_PORT} (connect, send "subdomain\\n", then raw TCP)`);
  });
  tcpServer.on("error", (err) => {
    console.error("TCP tunnel server error:", err.message);
  });
}

const requestHandler = async (req, res) => {
  const url = new URL(req.url || "/", `${protocol}://${req.headers.host}`);
  const upgrade = req.headers.upgrade?.toLowerCase();

  if (upgrade === "websocket" && url.pathname === "/_tunnel") {
    return;
  }

  const subdomain = extractSubdomain(req.headers.host);
  if (!subdomain) {
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(`
      <!DOCTYPE html>
      <html>
        <head><title>Global Tunnel</title></head>
        <body style="font-family: system-ui; max-width: 600px; margin: 4rem auto; padding: 2rem;">
          <h1>🌐 Global Tunnel</h1>
          <p>Run a client to expose your local server:</p>
          <pre style="background: #1e1e1e; color: #d4d4d4; padding: 1rem; border-radius: 8px;">npx global-tunnel --port 3000</pre>
          <p>Then open the URL shown by the client (e.g. <code>https://xxxx.${TUNNEL_DOMAIN}</code>).</p>
        </body>
      </html>
    `);
    return;
  }

  const tunnel = tunnels.get(subdomain);
  if (!tunnel || tunnel.ws.readyState !== 1) {
    res.writeHead(502, { "Content-Type": "text/plain" });
    res.end("No tunnel for this subdomain or tunnel disconnected.");
    return;
  }

  const body = await parseRequestBody(req);
  const requestId = randomBytes(8).toString("hex");

  const headers = { ...req.headers };
  delete headers["host"];
  const forwardHost = req.headers.host || "";
  headers["x-forwarded-host"] = forwardHost;
  headers["x-forwarded-proto"] = req.headers["x-forwarded-proto"] || protocol;

  const message = {
    type: "request",
    id: requestId,
    method: req.method,
    url: url.pathname + url.search,
    headers: headers,
    body: body.toString("base64"),
  };

  const responsePromise = new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      if (pendingRequests.has(requestId)) {
        pendingRequests.delete(requestId);
        reject(new Error("Request timeout"));
      }
    }, REQUEST_TIMEOUT_MS);

    pendingRequests.set(requestId, {
      resolve: (value) => {
        clearTimeout(timeout);
        pendingRequests.delete(requestId);
        resolve(value);
      },
      reject,
      timeout,
    });
  });

  try {
    tunnel.ws.send(JSON.stringify(message));
  } catch (err) {
    if (pendingRequests.has(requestId)) {
      const pending = pendingRequests.get(requestId);
      clearTimeout(pending.timeout);
      pendingRequests.delete(requestId);
    }
    res.writeHead(502, { "Content-Type": "text/plain" });
    res.end("Tunnel connection error.");
    return;
  }

  try {
    const { statusCode = 200, headers: resHeaders = {}, body: resBody = "" } =
      await responsePromise;

    const headersToSend = {};
    for (const [k, v] of Object.entries(resHeaders)) {
      const key = k.toLowerCase();
      if (
        key !== "transfer-encoding" &&
        key !== "connection" &&
        key !== "keep-alive"
      ) {
        headersToSend[k] = v;
      }
    }

    res.writeHead(statusCode, headersToSend);
    const buf =
      typeof resBody === "string" && /^[A-Za-z0-9+/=]+$/.test(resBody)
        ? Buffer.from(resBody, "base64")
        : Buffer.from(resBody, "utf8");
    res.end(buf);
  } catch (err) {
    res.writeHead(504, { "Content-Type": "text/plain" });
    res.end("Gateway timeout.");
  }
};

const server =
  useTls && tlsOptions
    ? https.createServer(tlsOptions, requestHandler)
    : http.createServer(requestHandler);

const wss = new WebSocketServer({ noServer: true });
const userWss = new WebSocketServer({ noServer: true });

server.on("upgrade", (request, socket, head) => {
  const url = new URL(request.url || "/", `${protocol}://${request.headers.host}`);
  if (url.pathname === "/_tunnel") {
    wss.handleUpgrade(request, socket, head, (ws) => {
      wss.emit("connection", ws, request);
    });
    return;
  }
  // Proxy other WebSockets (e.g. Vite HMR) through the tunnel to the local app
  const subdomain = extractSubdomain(request.headers.host);
  const tunnel = subdomain ? tunnels.get(subdomain) : null;
  if (!tunnel || tunnel.ws.readyState !== 1) {
    socket.destroy();
    return;
  }
  const id = randomBytes(8).toString("hex");
  userWss.handleUpgrade(request, socket, head, (browserWs) => {
    pendingProxiedWs.set(id, { browserWs, tunnelWs: tunnel.ws });
    const headers = { ...request.headers };
    delete headers["host"];
    delete headers["upgrade"];
    delete headers["connection"];
    delete headers["sec-websocket-key"];
    delete headers["sec-websocket-version"];
    delete headers["sec-websocket-extensions"];
    try {
      tunnel.ws.send(
        JSON.stringify({
          type: "ws-upgrade",
          id,
          path: url.pathname + url.search,
          headers,
        })
      );
    } catch (err) {
      browserWs.close();
      pendingProxiedWs.delete(id);
      return;
    }
    browserWs.on("message", (data) => {
      if (tunnel.ws.readyState !== 1) return;
      const payload = Buffer.isBuffer(data) ? data.toString("base64") : Buffer.from(data).toString("base64");
      tunnel.ws.send(JSON.stringify({ type: "ws-data", id, payload }));
    });
    browserWs.on("close", () => {
      if (tunnel.ws.readyState === 1) {
        tunnel.ws.send(JSON.stringify({ type: "ws-close", id }));
      }
      pendingProxiedWs.delete(id);
    });
    browserWs.on("error", () => {
      if (tunnel.ws.readyState === 1) {
        tunnel.ws.send(JSON.stringify({ type: "ws-close", id }));
      }
      pendingProxiedWs.delete(id);
    });
  });
});

wss.on("connection", (ws, req) => {
  let subdomain = null;

  ws.on("message", (data) => {
    try {
      const msg = JSON.parse(data.toString());
      if (msg.type === "register") {
        const requested = msg.subdomain != null ? normalizeSubdomain(msg.subdomain) : null;
        const validRequest = requested && isValidSubdomain(requested);
        const available = validRequest && !tunnels.has(requested);
        subdomain = available ? requested : generateSubdomain();
        const tcpPort = typeof msg.tcpPort === "number" && msg.tcpPort > 0 && msg.tcpPort <= 65535 ? msg.tcpPort : null;
        tunnels.set(subdomain, { ws, createdAt: Date.now(), tcpPort });
        const payload = {
          type: "registered",
          subdomain,
          url: `${advertisedProtocol}://${subdomain}.${TUNNEL_DOMAIN}${portSuffix}`,
          requestedSubdomain: requested || undefined,
          usedRequestedSubdomain: available,
        };
        if (TCP_TUNNEL_PORT > 0) {
          payload.tcpTunnelPort = TCP_TUNNEL_PORT;
          if (tcpPort != null) payload.tcpPort = tcpPort;
        }
        ws.send(JSON.stringify(payload));
        return;
      }
      if (msg.type === "response" && msg.id && pendingRequests.has(msg.id)) {
        pendingRequests.get(msg.id).resolve({
          statusCode: msg.status,
          headers: msg.headers || {},
          body: msg.body ?? "",
        });
        return;
      }
      if (msg.type === "ws-data" && msg.id && pendingProxiedWs.has(msg.id)) {
        const { browserWs } = pendingProxiedWs.get(msg.id);
        if (browserWs.readyState === 1) {
          browserWs.send(Buffer.from(msg.payload, "base64"));
        }
        return;
      }
      if (msg.type === "ws-close" && msg.id && pendingProxiedWs.has(msg.id)) {
        const { browserWs } = pendingProxiedWs.get(msg.id);
        pendingProxiedWs.delete(msg.id);
        if (browserWs.readyState === 1) browserWs.close();
        return;
      }
      // TCP tunnel: client confirms local connection ready
      if (msg.type === "tcp-connected" && msg.id && pendingTcpConnections.has(msg.id)) {
        const entry = pendingTcpConnections.get(msg.id);
        if (entry.connectTimeout) clearTimeout(entry.connectTimeout);
        entry.connectTimeout = null;
        entry.publicSocket.removeAllListeners("data");
        const id = msg.id;
        // Flush buffered data from public client (received before handshake completed)
        for (const chunk of entry.buffer) {
          if (entry.tunnelWs.readyState === 1) {
            entry.tunnelWs.send(JSON.stringify({ type: "tcp-data", id, payload: chunk.toString("base64") }));
          }
        }
        entry.buffer = [];
        entry.publicSocket.on("data", (chunk) => {
          if (entry.tunnelWs.readyState === 1) {
            entry.tunnelWs.send(JSON.stringify({ type: "tcp-data", id, payload: chunk.toString("base64") }));
          }
        });
        return;
      }
      if (msg.type === "tcp-error" && msg.id && pendingTcpConnections.has(msg.id)) {
        const entry = pendingTcpConnections.get(msg.id);
        pendingTcpConnections.delete(msg.id);
        if (entry.connectTimeout) clearTimeout(entry.connectTimeout);
        entry.publicSocket.destroy();
        return;
      }
      if (msg.type === "tcp-data" && msg.id && pendingTcpConnections.has(msg.id)) {
        const entry = pendingTcpConnections.get(msg.id);
        if (entry.publicSocket.writable) {
          entry.publicSocket.write(Buffer.from(msg.payload, "base64"));
        }
        return;
      }
      if (msg.type === "tcp-close" && msg.id && pendingTcpConnections.has(msg.id)) {
        const entry = pendingTcpConnections.get(msg.id);
        pendingTcpConnections.delete(msg.id);
        entry.publicSocket.destroy();
        return;
      }
    } catch (e) {
      console.error("Message error:", e.message);
    }
  });

  function closeProxiedForTunnel() {
    for (const [pid, entry] of pendingProxiedWs) {
      if (entry.tunnelWs === ws) {
        if (entry.browserWs.readyState === 1) entry.browserWs.close();
        pendingProxiedWs.delete(pid);
      }
    }
  }
  function closeTcpForTunnel() {
    for (const [id, entry] of pendingTcpConnections) {
      if (entry.tunnelWs === ws) {
        if (entry.connectTimeout) clearTimeout(entry.connectTimeout);
        entry.publicSocket.destroy();
        pendingTcpConnections.delete(id);
      }
    }
  }
  ws.on("close", () => {
    closeProxiedForTunnel();
    closeTcpForTunnel();
    if (subdomain) tunnels.delete(subdomain);
  });

  ws.on("error", () => {
    closeProxiedForTunnel();
    closeTcpForTunnel();
    if (subdomain) tunnels.delete(subdomain);
  });
});

server.listen(PORT, () => {
  console.log(
    `Global Tunnel server listening on port ${PORT} (${useTls && tlsOptions ? "HTTPS" : "HTTP"})`
  );
  console.log(
    `Public base: ${advertisedProtocol}://<subdomain>.${TUNNEL_DOMAIN}${portSuffix}`
  );
  if (TCP_TUNNEL_PORT > 0) {
    createTcpTunnelServer();
  }
});
