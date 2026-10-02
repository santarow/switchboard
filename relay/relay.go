// Package relay is Switchboard's message relay: devices log in with an Ed25519 key, then send
// sealed frames to each other's keys. The relay reads only the small routing header of a frame,
// never the sealed payload. Wire format: docs/protocol.md.
package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
)

const (
	maxHeader    = 2 << 10   // routing header of a binary frame
	maxPayload   = 256 << 10 // sealed bytes per frame; bigger messages go in several frames
	maxFrame     = 2 + maxHeader + maxPayload
	maxLossy     = 16 << 10 // one sealed 20 ms audio frame is well under 2 KB
	loginTimeout = 10 * time.Second
	pingEvery    = 30 * time.Second // Cloudflare drops idle sockets after about 100 s
	sendTimeout  = 10 * time.Second // how long a sender waits on a slow recipient
	replyPassFor = 2 * time.Minute  // a device that sent a ticketed frame may be answered this long
	queueFrames  = 32               // about 8 MB at most per connection
	queueLive    = 64               // live audio frames waiting; more are dropped, never queued behind
	ratePerSec   = 400              // frames per second per connection, with the same burst
	maxAllow     = 256              // keys in one policy
	maxTickets   = 64               // tickets in one policy
	maxGone      = 1024
)

var b64 = base64.RawURLEncoding

// Hub knows who is online and what each of them allows.
type Hub struct {
	mu        sync.Mutex
	conns     map[string]*conn
	gone      map[string]goneEntry    // policies of devices that went offline, to answer their peers
	replyPass map[[2]string]time.Time // {sender, recipient} → until
	perIP     map[string]int
	total     int
	now       func() time.Time
	logf      func(string, ...any)
	ice       []ICEServer

	// MaxConns and MaxConnsPerIP cap open connections, counted from before login; 0 means no cap.
	MaxConns, MaxConnsPerIP int

	// IPHeader names the header that carries the client's address when a proxy on this machine
	// (cloudflared) forwards the connection. It is trusted only from a loopback peer.
	IPHeader string

	// Host, when set, is the only host name a login may be signed for. Without it the request's
	// Host header is used, which is fine behind a proxy that routes by host name (Cloudflare
	// Tunnel) but lets a client name any host when the relay is reachable directly.
	Host string
}

// ICEServer is a STUN or TURN server the clients may use for direct calls, in WebRTC's shape.
type ICEServer struct {
	URLs []string `json:"urls"`
}

// NewHub makes a hub that tells clients about these ICE servers when they log in.
func NewHub(ice ...ICEServer) *Hub {
	return &Hub{conns: map[string]*conn{}, gone: map[string]goneEntry{}, replyPass: map[[2]string]time.Time{},
		perIP: map[string]int{}, now: time.Now, logf: log.Printf, ice: ice,
		MaxConns: 256, MaxConnsPerIP: 16, IPHeader: "CF-Connecting-IP"}
}

// policy is who may reach a device: its paired keys, and tickets for pairing codes on screen.
type policy struct {
	allow   map[string]bool
	tickets map[string]time.Time // sha256(code) hex → expiry
}

type goneEntry struct {
	pol policy
	at  time.Time
}

type conn struct {
	id   string
	ws   *websocket.Conn
	out  chan outFrame
	live chan outFrame // lossy frames: sent before out, dropped when full
	done chan struct{}
	pol  policy
}

type outFrame struct {
	typ  websocket.MessageType
	data []byte
}

// Header is the routing header in front of every sealed payload. The relay sets From itself.
type Header struct {
	To     string `json:"to"`
	From   string `json:"from,omitempty"`
	ID     string `json:"id"`
	Seq    int    `json:"seq"`
	Last   bool   `json:"last"`
	Key    string `json:"key,omitempty"`
	Ticket string `json:"ticket,omitempty"`
	Lossy  bool   `json:"lossy,omitempty"` // live audio: drop rather than wait, and go first
}

type control struct {
	T       string   `json:"t"`
	ID      string   `json:"id,omitempty"`
	Sig     string   `json:"sig,omitempty"`
	Allow   []string `json:"allow,omitempty"`
	Tickets []struct {
		Hash string `json:"hash"`
		Exp  int64  `json:"exp"`
	} `json:"tickets,omitempty"`
}

// LoginMessage is what a device signs to prove it holds its key.
func LoginMessage(host string, nonce []byte) []byte {
	return append([]byte("switchboard-v1 login\n"+host+"\n"), nonce...)
}

// ServeHTTP handles /v1/connect.
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ip := h.clientIP(r)
	if status := h.admit(ip); status != 0 {
		http.Error(w, http.StatusText(status), status)
		return
	}
	defer h.release(ip)
	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	ws.SetReadLimit(maxFrame)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	host := r.Host
	if h.Host != "" {
		host = h.Host
	}
	id, err := h.login(ctx, ws, host)
	if err != nil {
		ws.Close(websocket.StatusPolicyViolation, "login failed")
		return
	}
	c := &conn{id: id, ws: ws, out: make(chan outFrame, queueFrames), live: make(chan outFrame, queueLive), done: make(chan struct{}),
		pol: policy{allow: map[string]bool{}, tickets: map[string]time.Time{}}}

	h.mu.Lock()
	old := h.conns[id]
	h.conns[id] = c
	delete(h.gone, id)
	online := len(h.conns)
	h.mu.Unlock()
	if old != nil {
		// Close waits for the old peer's answer, so never under the hub lock.
		go old.ws.Close(websocket.StatusGoingAway, "replaced by a newer connection")
	}
	h.logf("connect %s (%d online)", short(id), online)

	go c.writer(ctx, cancel)
	c.sendJSON(map[string]any{"t": "ready", "id": id, "ice": h.ice})
	err = h.reader(ctx, c)

	close(c.done)
	h.mu.Lock()
	if h.conns[id] == c {
		delete(h.conns, id)
		h.remember(id, c.pol)
	}
	online = len(h.conns)
	h.mu.Unlock()
	h.logf("disconnect %s (%d online): %v", short(id), online, websocket.CloseStatus(err))
	ws.CloseNow()
}

// clientIP is the address connection limits count against.
func (h *Hub) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); h.IPHeader != "" && ip != nil && ip.IsLoopback() {
		if v := r.Header.Get(h.IPHeader); v != "" {
			return v
		}
	}
	return host
}

// admit takes a connection slot for ip, or says which status to refuse with.
func (h *Hub) admit(ip string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.MaxConns > 0 && h.total >= h.MaxConns {
		h.logf("refused: full (%d connections)", h.total)
		return http.StatusServiceUnavailable
	}
	if h.MaxConnsPerIP > 0 && h.perIP[ip] >= h.MaxConnsPerIP {
		h.logf("refused: too many connections from one address")
		return http.StatusTooManyRequests
	}
	h.total++
	h.perIP[ip]++
	return 0
}

func (h *Hub) release(ip string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.total--
	if h.perIP[ip]--; h.perIP[ip] <= 0 {
		delete(h.perIP, ip)
	}
}

// remember keeps a disconnected device's policy, so its paired peers hear "offline" and everyone
// else "not_allowed". Memory only, oldest dropped first. Call with h.mu held.
func (h *Hub) remember(id string, p policy) {
	if len(h.gone) >= maxGone {
		oldest, at := "", h.now()
		for k, g := range h.gone {
			if !g.at.After(at) {
				oldest, at = k, g.at
			}
		}
		delete(h.gone, oldest)
	}
	h.gone[id] = goneEntry{p, h.now()}
}

func (h *Hub) login(ctx context.Context, ws *websocket.Conn, host string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, loginTimeout)
	defer cancel()
	nonce := make([]byte, 32)
	rand.Read(nonce)
	msg, _ := json.Marshal(map[string]string{"t": "challenge", "nonce": b64.EncodeToString(nonce)})
	if err := ws.Write(ctx, websocket.MessageText, msg); err != nil {
		return "", err
	}
	typ, data, err := ws.Read(ctx)
	if err != nil || typ != websocket.MessageText {
		return "", errors.New("no login")
	}
	var m control
	if json.Unmarshal(data, &m) != nil || m.T != "login" {
		return "", errors.New("bad login")
	}
	pub, ok := decodeKey(m.ID)
	sig, err := b64.DecodeString(m.Sig)
	if !ok || err != nil || !ed25519.Verify(ed25519.PublicKey(pub), LoginMessage(host, nonce), sig) {
		return "", errors.New("bad signature")
	}
	return m.ID, nil
}

func (h *Hub) reader(ctx context.Context, c *conn) error {
	tokens, last := float64(ratePerSec), h.now()
	for {
		typ, data, err := c.ws.Read(ctx)
		if err != nil {
			return err
		}
		now := h.now()
		tokens = min(ratePerSec, tokens+now.Sub(last).Seconds()*ratePerSec)
		last = now
		if tokens < 1 {
			c.sendJSON(map[string]any{"t": "error", "error": "rate_limited"})
			continue
		}
		tokens--
		if typ == websocket.MessageText {
			h.control(c, data)
		} else {
			h.forward(ctx, c, data)
		}
	}
}

func (h *Hub) control(c *conn, data []byte) {
	var m control
	if json.Unmarshal(data, &m) != nil || m.T != "policy" {
		c.sendJSON(map[string]any{"t": "error", "error": "bad_control"})
		return
	}
	if len(m.Allow) > maxAllow || len(m.Tickets) > maxTickets {
		c.sendJSON(map[string]any{"t": "error", "error": "too_big"}) // the previous policy stays
		return
	}
	allow := map[string]bool{}
	for _, k := range m.Allow {
		if _, ok := decodeKey(k); ok {
			allow[k] = true
		}
	}
	tickets := map[string]time.Time{}
	for _, t := range m.Tickets {
		if len(t.Hash) == 64 {
			tickets[t.Hash] = time.Unix(t.Exp, 0)
		}
	}
	h.mu.Lock()
	c.pol = policy{allow, tickets}
	h.mu.Unlock()
}

func (h *Hub) forward(ctx context.Context, c *conn, data []byte) {
	if len(data) < 2 {
		return
	}
	n := int(binary.BigEndian.Uint16(data))
	if n > maxHeader || 2+n > len(data) || len(data)-2-n > maxPayload {
		c.sendJSON(map[string]any{"t": "error", "error": "too_big"})
		return
	}
	var hd Header
	if json.Unmarshal(data[2:2+n], &hd) != nil || hd.ID == "" {
		c.sendJSON(map[string]any{"t": "error", "error": "bad_frame"})
		return
	}
	fail := func(e string) { c.sendJSON(map[string]any{"t": "error", "re": hd.ID, "error": e}) }
	if hd.Lossy && len(data)-2-n > maxLossy {
		fail("too_big")
		return
	}

	// Whether the recipient is online is told only to senders it allows, online or not.
	h.mu.Lock()
	to := h.conns[hd.To]
	var ok bool
	if to != nil {
		ok = h.allowed(c.id, to.id, to.pol, hd.Ticket)
	} else if g, found := h.gone[hd.To]; found {
		ok = h.allowed(c.id, hd.To, g.pol, hd.Ticket)
	}
	if ok && to != nil && hd.Ticket != "" {
		now := h.now()
		for k, until := range h.replyPass { // ticketed frames are rare (pairing), so a sweep is cheap
			if !now.Before(until) {
				delete(h.replyPass, k)
			}
		}
		h.replyPass[[2]string{to.id, c.id}] = now.Add(replyPassFor)
	}
	h.mu.Unlock()
	if !ok {
		fail("not_allowed")
		return
	}
	if to == nil {
		fail("offline")
		return
	}

	hd.From, hd.Ticket = c.id, ""
	head, _ := json.Marshal(hd)
	frame := make([]byte, 2, 2+len(head)+len(data)-2-n)
	binary.BigEndian.PutUint16(frame, uint16(len(head)))
	frame = append(append(frame, head...), data[2+n:]...)

	if hd.Lossy {
		select {
		case to.live <- outFrame{websocket.MessageBinary, frame}:
		default: // the recipient is behind; late audio is worse than lost audio
		}
		return
	}
	t := time.NewTimer(sendTimeout)
	defer t.Stop()
	select {
	case to.out <- outFrame{websocket.MessageBinary, frame}:
	case <-to.done:
		fail("offline")
	case <-t.C:
		fail("slow")
	case <-ctx.Done():
	}
}

// allowed says whether sender may reach the device to, whose policy is p. Call with h.mu held.
func (h *Hub) allowed(sender, to string, p policy, ticket string) bool {
	now := h.now()
	if p.allow[sender] {
		return true
	}
	if exp, ok := p.tickets[ticket]; ticket != "" && ok && now.Before(exp) {
		return true
	}
	if until, ok := h.replyPass[[2]string{sender, to}]; ok {
		if now.Before(until) {
			return true
		}
		delete(h.replyPass, [2]string{sender, to})
	}
	return false
}

// writer is the only goroutine that writes to the socket. Live audio goes before anything queued.
func (c *conn) writer(ctx context.Context, cancel context.CancelFunc) {
	defer cancel()
	ping := time.NewTicker(pingEvery)
	defer ping.Stop()
	for {
		var f outFrame
		select {
		case f = <-c.live:
		default:
			select {
			case f = <-c.live:
			case f = <-c.out:
			case <-ping.C:
				pctx, pcancel := context.WithTimeout(ctx, sendTimeout)
				err := c.ws.Ping(pctx)
				pcancel()
				if err != nil {
					return
				}
				continue
			case <-ctx.Done():
				return
			}
		}
		wctx, wcancel := context.WithTimeout(ctx, sendTimeout)
		err := c.ws.Write(wctx, f.typ, f.data)
		wcancel()
		if err != nil {
			return
		}
	}
}

// sendJSON queues a control message without blocking; it is dropped if the queue is full.
func (c *conn) sendJSON(v any) {
	data, _ := json.Marshal(v)
	select {
	case c.out <- outFrame{websocket.MessageText, data}:
	default:
	}
}

func decodeKey(s string) ([]byte, bool) {
	k, err := b64.DecodeString(s)
	return k, err == nil && len(k) == 32
}

// short is enough of a key to tell devices apart in logs.
func short(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
