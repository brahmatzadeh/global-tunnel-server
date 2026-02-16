// Tunnel Server (Go)
// Accepts WebSocket connections from tunnel clients and forwards HTTP traffic
// from the public internet to the appropriate client based on subdomain.
// Optional TCP tunnel: public clients connect to TCP_TUNNEL_PORT, send "subdomain\n", then raw TCP is proxied to the client's local port.

package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/joho/godotenv"
)

const (
	requestTimeoutMs       = 60_000
	tcpConnectTimeoutMs    = 15_000
	tcpHandshakeTimeoutMs  = 5_000
	subdomainMaxLen       = 63
)

var subdomainRegex = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)

type tunnelEntry struct {
	ws        *websocket.Conn
	createdAt int64
	tcpPort   *int
}

type pendingRequest struct {
	resolve  func(responsePayload)
	reject   func()
	timeout  *time.Timer
}

type responsePayload struct {
	StatusCode int               `json:"status"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
}

type pendingProxiedWs struct {
	browserWs *websocket.Conn
	tunnelWs  *websocket.Conn
}

type pendingTcpConn struct {
	publicSocket   net.Conn
	tunnelWs       *websocket.Conn
	buffer         [][]byte
	connectTimeout *time.Timer
}

type serverState struct {
	port              int
	tunnelDomain      string
	tcpTunnelPort     int
	publicPort        int
	publicProtocol    string
	useTls            bool
	protocol          string
	portSuffix        string
	advertisedProtocol string
	tlsCertPath       string
	tlsKeyPath        string

	mu                 sync.RWMutex
	tunnels            map[string]*tunnelEntry
	pendingRequests    map[string]*pendingRequest
	pendingProxiedWs   map[string]*pendingProxiedWs
	pendingTcpConns   map[string]*pendingTcpConn
}

func (s *serverState) generateSubdomain() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func isValidSubdomain(sub string) bool {
	if sub == "" || len(sub) > subdomainMaxLen {
		return false
	}
	return subdomainRegex.MatchString(sub)
}

func normalizeSubdomain(sub string) string {
	return strings.ToLower(strings.TrimSpace(sub))
}

func extractSubdomain(host string) string {
	if host == "" {
		return ""
	}
	hostname := host
	if idx := strings.Index(host, ":"); idx >= 0 {
		hostname = host[:idx]
	}
	parts := strings.Split(hostname, ".")
	if len(parts) >= 2 {
		return parts[0]
	}
	if hostname == "localhost" || hostname == "127.0.0.1" {
		return ""
	}
	return hostname
}

func loadEnv() {
	_ = godotenv.Load()
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		n, _ := strconv.Atoi(v)
		return n
	}
	return def
}

func main() {
	loadEnv()

	port := getEnvInt("PORT", 443)
	tunnelDomain := getEnv("TUNNEL_DOMAIN", "localhost")
	tcpTunnelPort := getEnvInt("TCP_TUNNEL_PORT", 0)
	publicPort := port
	if v := os.Getenv("PUBLIC_PORT"); v != "" {
		publicPort, _ = strconv.Atoi(v)
	}
	publicProtocol := getEnv("PUBLIC_PROTOCOL", "")
	if publicProtocol == "" {
		if publicPort == 443 {
			publicProtocol = "https"
		} else if publicPort == 80 {
			publicProtocol = "http"
		} else {
			publicProtocol = "http"
		}
	}

	tlsCertPath := getEnv("TLS_CERT_PATH", getEnv("TLS_CERT", ""))
	tlsKeyPath := getEnv("TLS_KEY_PATH", getEnv("TLS_KEY", ""))
	useTls := port == 443 && tlsCertPath != "" && tlsKeyPath != ""

	protocol := "http"
	if useTls {
		protocol = "https"
	}
	portSuffix := ""
	if publicPort != 80 && publicPort != 443 {
		portSuffix = ":" + strconv.Itoa(publicPort)
	}

	s := &serverState{
		port:                port,
		tunnelDomain:        tunnelDomain,
		tcpTunnelPort:       tcpTunnelPort,
		publicPort:          publicPort,
		publicProtocol:      publicProtocol,
		useTls:              useTls,
		protocol:            protocol,
		portSuffix:          portSuffix,
		advertisedProtocol:  publicProtocol,
		tlsCertPath:         tlsCertPath,
		tlsKeyPath:          tlsKeyPath,
		tunnels:             make(map[string]*tunnelEntry),
		pendingRequests:     make(map[string]*pendingRequest),
		pendingProxiedWs:    make(map[string]*pendingProxiedWs),
		pendingTcpConns:     make(map[string]*pendingTcpConn),
	}

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	userUpgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.handleHTTP(w, r, &upgrader, &userUpgrader)
	})

	var tlsConfig *struct{ certFile, keyFile string }
	if useTls {
		tlsConfig = &struct{ certFile, keyFile string }{tlsCertPath, tlsKeyPath}
	}

	addr := ":" + strconv.Itoa(port)
	log.Printf("Global Tunnel server listening on port %d (%s)", port, map[bool]string{true: "HTTPS", false: "HTTP"}[useTls && tlsConfig != nil])
	log.Printf("Public base: %s://<subdomain>.%s%s", s.advertisedProtocol, tunnelDomain, portSuffix)

	if tcpTunnelPort > 0 {
		go s.runTcpTunnelServer()
	}

	var err error
	if tlsConfig != nil {
		err = http.ListenAndServeTLS(addr, tlsConfig.certFile, tlsConfig.keyFile, mux)
	} else {
		err = http.ListenAndServe(addr, mux)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func (s *serverState) handleHTTP(w http.ResponseWriter, r *http.Request, upgrader, userUpgrader *websocket.Upgrader) {
	u, _ := url.Parse(r.URL.String())
	u.Host = r.Host
	u.Scheme = s.protocol
	if u.Path == "" {
		u.Path = "/"
	}

	upgrade := strings.ToLower(r.Header.Get("Upgrade"))

	if upgrade == "websocket" && r.URL.Path == "/_tunnel" {
		// Tunnel client WebSocket; handle in upgrade path below
		s.handleTunnelUpgrade(w, r, upgrader)
		return
	}

	subdomain := extractSubdomain(r.Host)
	if subdomain == "" {
		s.serveLanding(w)
		return
	}

	s.mu.RLock()
	tunnel := s.tunnels[subdomain]
	s.mu.RUnlock()

	if tunnel == nil || tunnel.ws == nil {
		http.Error(w, "No tunnel for this subdomain or tunnel disconnected.", http.StatusBadGateway)
		return
	}

	// Check if this is a WebSocket upgrade (e.g. Vite HMR) to proxy
	if upgrade == "websocket" {
		s.handleUserWsUpgrade(w, r, userUpgrader, subdomain, u)
		return
	}

	// HTTP request: forward to tunnel client
	body, _ := io.ReadAll(r.Body)
	requestId := randomHex(8)

	headers := make(map[string]string)
	for k, v := range r.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}
	delete(headers, "Host")
	forwardHost := r.Host
	headers["X-Forwarded-Host"] = forwardHost
	headers["X-Forwarded-Proto"] = r.Header.Get("X-Forwarded-Proto")
	if headers["X-Forwarded-Proto"] == "" {
		headers["X-Forwarded-Proto"] = s.protocol
	}

	msg := map[string]interface{}{
		"type":    "request",
		"id":      requestId,
		"method":  r.Method,
		"url":     u.Path + u.RawQuery,
		"headers": headers,
		"body":    base64.StdEncoding.EncodeToString(body),
	}
	msgBytes, _ := json.Marshal(msg)

	ctx, cancel := context.WithTimeout(r.Context(), requestTimeoutMs*time.Millisecond)
	defer cancel()

	done := make(chan responsePayload, 1)
	fail := make(chan struct{}, 1)

	timeout := time.AfterFunc(requestTimeoutMs*time.Millisecond, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if p, ok := s.pendingRequests[requestId]; ok {
			delete(s.pendingRequests, requestId)
			if p.timeout != nil {
				p.timeout.Stop()
			}
			select { case fail <- struct{}{}: default: }
		}
	})

	s.mu.Lock()
	s.pendingRequests[requestId] = &pendingRequest{
		resolve: func(rp responsePayload) {
			timeout.Stop()
			select { case done <- rp: default: }
		},
		reject:  func() { select { case fail <- struct{}{}: default: } },
		timeout: timeout,
	}
	s.mu.Unlock()

	if err := tunnel.ws.WriteMessage(websocket.TextMessage, msgBytes); err != nil {
		s.mu.Lock()
		delete(s.pendingRequests, requestId)
		timeout.Stop()
		s.mu.Unlock()
		http.Error(w, "Tunnel connection error.", http.StatusBadGateway)
		return
	}

	select {
	case rp := <-done:
		s.mu.Lock()
		delete(s.pendingRequests, requestId)
		s.mu.Unlock()

		h := w.Header()
		for k, v := range rp.Headers {
			kl := strings.ToLower(k)
			if kl != "transfer-encoding" && kl != "connection" && kl != "keep-alive" {
				h.Set(k, v)
			}
		}
		status := rp.StatusCode
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		decoded, err := base64.StdEncoding.DecodeString(rp.Body)
		if err == nil && len(rp.Body) > 0 && isBase64(rp.Body) {
			w.Write(decoded)
		} else {
			w.Write([]byte(rp.Body))
		}
	case <-fail:
		http.Error(w, "Gateway timeout.", http.StatusGatewayTimeout)
	case <-ctx.Done():
		http.Error(w, "Gateway timeout.", http.StatusGatewayTimeout)
	}
}

func isBase64(s string) bool {
	for _, c := range s {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' {
			continue
		}
		return false
	}
	return true
}

func (s *serverState) serveLanding(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	html := `<!DOCTYPE html>
<html>
  <head><title>Global Tunnel</title></head>
  <body style="font-family: system-ui; max-width: 600px; margin: 4rem auto; padding: 2rem;">
    <h1>🌐 Global Tunnel</h1>
    <p>Run a client to expose your local server:</p>
    <pre style="background: #1e1e1e; color: #d4d4d4; padding: 1rem; border-radius: 8px;">npx global-tunnel --port 3000</pre>
    <p>Then open the URL shown by the client (e.g. <code>https://xxxx.` + s.tunnelDomain + `</code>).</p>
  </body>
</html>`
	w.Write([]byte(html))
}

func (s *serverState) handleTunnelUpgrade(w http.ResponseWriter, r *http.Request, upgrader *websocket.Upgrader) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	s.handleTunnelConnection(ws)
}

func (s *serverState) handleUserWsUpgrade(w http.ResponseWriter, r *http.Request, upgrader *websocket.Upgrader, subdomain string, u *url.URL) {
	s.mu.RLock()
	tunnel := s.tunnels[subdomain]
	s.mu.RUnlock()
	if tunnel == nil || tunnel.ws == nil {
		http.Error(w, "No tunnel", http.StatusBadGateway)
		return
	}

	browserWs, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	id := randomHex(8)
	headers := make(map[string]string)
	for k, v := range r.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}
	delete(headers, "Host")
	delete(headers, "Upgrade")
	delete(headers, "Connection")
	delete(headers, "Sec-Websocket-Key")
	delete(headers, "Sec-Websocket-Version")
	delete(headers, "Sec-Websocket-Extensions")

	s.mu.Lock()
	s.pendingProxiedWs[id] = &pendingProxiedWs{browserWs: browserWs, tunnelWs: tunnel.ws}
	s.mu.Unlock()

	upgradeMsg := map[string]interface{}{
		"type":   "ws-upgrade",
		"id":     id,
		"path":   u.Path + u.RawQuery,
		"headers": headers,
	}
	upgradeBytes, _ := json.Marshal(upgradeMsg)
	if err := tunnel.ws.WriteMessage(websocket.TextMessage, upgradeBytes); err != nil {
		browserWs.Close()
		s.mu.Lock()
		delete(s.pendingProxiedWs, id)
		s.mu.Unlock()
		return
	}

	go func() {
		defer func() {
			s.mu.Lock()
			delete(s.pendingProxiedWs, id)
			s.mu.Unlock()
			browserWs.Close()
		}()
		for {
			mt, data, err := browserWs.ReadMessage()
			if err != nil {
				s.sendTunnelWsClose(tunnel.ws, id)
				return
			}
			if mt == websocket.TextMessage || mt == websocket.BinaryMessage {
				payload := base64.StdEncoding.EncodeToString(data)
				msg := map[string]interface{}{"type": "ws-data", "id": id, "payload": payload}
				msgBytes, _ := json.Marshal(msg)
				s.mu.RLock()
				t := s.tunnels[subdomain]
				s.mu.RUnlock()
				if t != nil && t.ws != nil {
					t.ws.WriteMessage(websocket.TextMessage, msgBytes)
				}
			}
		}
	}()
}

func (s *serverState) sendTunnelWsClose(tunnelWs *websocket.Conn, id string) {
	if tunnelWs == nil {
		return
	}
	msg := map[string]interface{}{"type": "ws-close", "id": id}
	msgBytes, _ := json.Marshal(msg)
	tunnelWs.WriteMessage(websocket.TextMessage, msgBytes)
}

func (s *serverState) handleTunnelConnection(ws *websocket.Conn) {
	var subdomain string
	defer func() {
		s.closeProxiedForTunnel(ws)
		s.closeTcpForTunnel(ws)
		if subdomain != "" {
			s.mu.Lock()
			delete(s.tunnels, subdomain)
			s.mu.Unlock()
		}
		ws.Close()
	}()

	for {
		_, data, err := ws.ReadMessage()
		if err != nil {
			return
		}

		var msg struct {
			Type    string `json:"type"`
			ID      string `json:"id"`
			Subdomain *string `json:"subdomain"`
			Status  int    `json:"status"`
			Headers map[string]string `json:"headers"`
			Body    string `json:"body"`
			Payload string `json:"payload"`
			Port    int    `json:"port"`
			TcpPort *int   `json:"tcpPort"`
		}
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}

		switch msg.Type {
		case "register":
			requested := ""
			if msg.Subdomain != nil {
				requested = normalizeSubdomain(*msg.Subdomain)
			}
			validRequest := requested != "" && isValidSubdomain(requested)
			s.mu.Lock()
			available := validRequest && s.tunnels[requested] == nil
			if available {
				subdomain = requested
			} else {
				subdomain = s.generateSubdomain()
			}
			tcpPort := msg.TcpPort
			if tcpPort != nil && (*tcpPort <= 0 || *tcpPort > 65535) {
				tcpPort = nil
			}
			s.tunnels[subdomain] = &tunnelEntry{ws: ws, createdAt: time.Now().UnixMilli(), tcpPort: tcpPort}
			s.mu.Unlock()

			payload := map[string]interface{}{
				"type":                   "registered",
				"subdomain":              subdomain,
				"url":                    s.advertisedProtocol + "://" + subdomain + "." + s.tunnelDomain + s.portSuffix,
				"usedRequestedSubdomain": available,
			}
			if requested != "" {
				payload["requestedSubdomain"] = requested
			}
			if s.tcpTunnelPort > 0 {
				payload["tcpTunnelPort"] = s.tcpTunnelPort
				if tcpPort != nil {
					payload["tcpPort"] = *tcpPort
				}
			}
			respBytes, _ := json.Marshal(payload)
			ws.WriteMessage(websocket.TextMessage, respBytes)

		case "response":
			if msg.ID == "" {
				break
			}
			s.mu.Lock()
			p, ok := s.pendingRequests[msg.ID]
			if ok {
				delete(s.pendingRequests, msg.ID)
				if p.timeout != nil {
					p.timeout.Stop()
				}
			}
			s.mu.Unlock()
			if ok && p.resolve != nil {
				status := msg.Status
				if status == 0 {
					status = 200
				}
				p.resolve(responsePayload{StatusCode: status, Headers: msg.Headers, Body: msg.Body})
			}

		case "ws-data":
			if msg.ID == "" {
				break
			}
			s.mu.RLock()
			entry := s.pendingProxiedWs[msg.ID]
			s.mu.RUnlock()
			if entry != nil && entry.browserWs != nil {
				decoded, _ := base64.StdEncoding.DecodeString(msg.Payload)
				entry.browserWs.WriteMessage(websocket.BinaryMessage, decoded)
			}

		case "ws-close":
			if msg.ID == "" {
				break
			}
			s.mu.Lock()
			entry := s.pendingProxiedWs[msg.ID]
			delete(s.pendingProxiedWs, msg.ID)
			s.mu.Unlock()
			if entry != nil && entry.browserWs != nil {
				entry.browserWs.Close()
			}

		case "tcp-connected":
			if msg.ID == "" {
				break
			}
			s.mu.Lock()
			conn := s.pendingTcpConns[msg.ID]
			if conn != nil {
				if conn.connectTimeout != nil {
					conn.connectTimeout.Stop()
					conn.connectTimeout = nil
				}
				for _, chunk := range conn.buffer {
					tcMsg := map[string]interface{}{"type": "tcp-data", "id": msg.ID, "payload": base64.StdEncoding.EncodeToString(chunk)}
					tcBytes, _ := json.Marshal(tcMsg)
					conn.tunnelWs.WriteMessage(websocket.TextMessage, tcBytes)
				}
				conn.buffer = nil
			}
			s.mu.Unlock()

		case "tcp-error":
			if msg.ID == "" {
				break
			}
			s.mu.Lock()
			conn := s.pendingTcpConns[msg.ID]
			delete(s.pendingTcpConns, msg.ID)
			s.mu.Unlock()
			if conn != nil {
				if conn.connectTimeout != nil {
					conn.connectTimeout.Stop()
				}
				conn.publicSocket.Close()
			}

		case "tcp-data":
			if msg.ID == "" {
				break
			}
			s.mu.RLock()
			conn := s.pendingTcpConns[msg.ID]
			s.mu.RUnlock()
			if conn != nil {
				decoded, _ := base64.StdEncoding.DecodeString(msg.Payload)
				conn.publicSocket.Write(decoded)
			}

		case "tcp-close":
			if msg.ID == "" {
				break
			}
			s.mu.Lock()
			conn := s.pendingTcpConns[msg.ID]
			delete(s.pendingTcpConns, msg.ID)
			s.mu.Unlock()
			if conn != nil {
				conn.publicSocket.Close()
			}
		}
	}
}

func (s *serverState) closeProxiedForTunnel(tunnelWs *websocket.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, entry := range s.pendingProxiedWs {
		if entry.tunnelWs == tunnelWs && entry.browserWs != nil {
			entry.browserWs.Close()
			delete(s.pendingProxiedWs, id)
		}
	}
}

func (s *serverState) closeTcpForTunnel(tunnelWs *websocket.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, conn := range s.pendingTcpConns {
		if conn.tunnelWs == tunnelWs {
			if conn.connectTimeout != nil {
				conn.connectTimeout.Stop()
			}
			conn.publicSocket.Close()
			delete(s.pendingTcpConns, id)
		}
	}
}

func (s *serverState) runTcpTunnelServer() {
	ln, err := net.Listen("tcp", ":"+strconv.Itoa(s.tcpTunnelPort))
	if err != nil {
		log.Printf("TCP tunnel listen error: %v", err)
		return
	}
	log.Printf("TCP tunnel listening on port %d (connect, send \"subdomain\\n\", then raw TCP)", s.tcpTunnelPort)
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go s.handleTcpTunnelConn(conn)
	}
}

func (s *serverState) handleTcpTunnelConn(publicSocket net.Conn) {
	handshakeDone := false
	var buf []byte
	handshakeTimeout := time.AfterFunc(tcpHandshakeTimeoutMs*time.Millisecond, func() {
		if !handshakeDone {
			handshakeDone = true
			publicSocket.Close()
		}
	})
	defer handshakeTimeout.Stop()

	readBuf := make([]byte, 4096)
	for !handshakeDone {
		n, err := publicSocket.Read(readBuf)
		if err != nil {
			return
		}
		buf = append(buf, readBuf[:n]...)
		idx := bytesIndexByte(buf, '\n')
		if idx < 0 {
			continue
		}
		handshakeDone = true
		handshakeTimeout.Stop()
		line := strings.TrimSpace(string(buf[:idx]))
		rest := buf[idx+1:]
		subdomain := normalizeSubdomain(line)
		if subdomain == "" || !isValidSubdomain(subdomain) {
			publicSocket.Close()
			return
		}
		s.mu.RLock()
		tunnel := s.tunnels[subdomain]
		s.mu.RUnlock()
		if tunnel == nil || tunnel.ws == nil || tunnel.tcpPort == nil {
			publicSocket.Close()
			return
		}
		id := randomHex(8)
		entry := &pendingTcpConn{
			publicSocket: publicSocket,
			tunnelWs:     tunnel.ws,
			buffer:       nil,
		}
		if len(rest) > 0 {
			entry.buffer = [][]byte{rest}
		}
		entry.connectTimeout = time.AfterFunc(tcpConnectTimeoutMs*time.Millisecond, func() {
			s.mu.Lock()
			if _, ok := s.pendingTcpConns[id]; ok {
				delete(s.pendingTcpConns, id)
				publicSocket.Close()
			}
			s.mu.Unlock()
		})

		s.mu.Lock()
		s.pendingTcpConns[id] = entry
		s.mu.Unlock()

		connectMsg := map[string]interface{}{"type": "tcp-connect", "id": id, "port": *tunnel.tcpPort}
		connectBytes, _ := json.Marshal(connectMsg)
		if err := tunnel.ws.WriteMessage(websocket.TextMessage, connectBytes); err != nil {
			s.mu.Lock()
			delete(s.pendingTcpConns, id)
			entry.connectTimeout.Stop()
			s.mu.Unlock()
			publicSocket.Close()
			return
		}

		// Forward public -> tunnel
		go func() {
			for {
				b := make([]byte, 32*1024)
				n, err := publicSocket.Read(b)
				if err != nil {
					break
				}
				s.mu.RLock()
				conn, ok := s.pendingTcpConns[id]
				s.mu.RUnlock()
				if !ok || conn.tunnelWs == nil {
					break
				}
				// If we're still in handshake buffer phase, tunnel handles flush after tcp-connected
				if conn.connectTimeout != nil {
					s.mu.Lock()
					conn.buffer = append(conn.buffer, b[:n])
					s.mu.Unlock()
				} else {
					payload := base64.StdEncoding.EncodeToString(b[:n])
					tcMsg := map[string]interface{}{"type": "tcp-data", "id": id, "payload": payload}
					tcBytes, _ := json.Marshal(tcMsg)
					conn.tunnelWs.WriteMessage(websocket.TextMessage, tcBytes)
				}
			}
			s.mu.Lock()
			if conn, ok := s.pendingTcpConns[id]; ok {
				delete(s.pendingTcpConns, id)
				if conn.connectTimeout != nil {
					conn.connectTimeout.Stop()
				}
				if conn.tunnelWs != nil {
					closeMsg := map[string]interface{}{"type": "tcp-close", "id": id}
					closeBytes, _ := json.Marshal(closeMsg)
					conn.tunnelWs.WriteMessage(websocket.TextMessage, closeBytes)
				}
			}
			s.mu.Unlock()
			publicSocket.Close()
		}()

		return
	}
}

func bytesIndexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}

func randomHex(n int) string {
	b := make([]byte, (n+1)/2)
	rand.Read(b)
	return hex.EncodeToString(b)[:n]
}
