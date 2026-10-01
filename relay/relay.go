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
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
)

const (
	maxHeader    = 2 << 10   // routing header of a binary frame
	maxPayload   = 256 << 10 // sealed bytes per frame; bigger messages go in several frames
	maxFrame     = 2 + maxHeader + maxPayload
	loginTimeout = 10 * time.Second
	pingEvery    = 30 * time.Second // Cloudflare drops idle sockets after about 100 s
	sendTimeout  = 10 * time.Second // how long a sender waits on a slow recipient
	replyPassFor = 2 * time.Minute  // a device that sent a ticketed frame may be answered this long
	queueFrames  = 256
	ratePerSec   = 400 // frames per second per connection, with the same burst
)

var b64 = base64.RawURLEncoding

// Hub knows who is online and what each of them allows.
type Hub struct {
	mu        sync.Mutex
	conns     map[string]*conn
	replyPass map[[2]string]time.Time // {sender, recipient} → until
	now       func() time.Time
	logf      func(string, ...any)
}

func NewHub() *Hub {
	return &Hub{conns: map[string]*conn{}, replyPass: map[[2]string]time.Time{}, now: time.Now, logf: log.Printf}
}

type conn struct {
	id      string
	ws      *websocket.Conn
	out     chan outFrame
	done    chan struct{}
	allow   map[string]bool
	tickets map[string]time.Time // sha256(code) hex → expiry
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
	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	ws.SetReadLimit(maxFrame)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	id, err := h.login(ctx, ws, r.Host)
	if err != nil {
		ws.Close(websocket.StatusPolicyViolation, "login failed")
		return
	}
	c := &conn{id: id, ws: ws, out: make(chan outFrame, queueFrames), done: make(chan struct{}),
		allow: map[string]bool{}, tickets: map[string]time.Time{}}

	h.mu.Lock()
	if old := h.conns[id]; old != nil {
		old.ws.Close(websocket.StatusGoingAway, "replaced by a newer connection")
	}
	h.conns[id] = c
	online := len(h.conns)
	h.mu.Unlock()
	h.logf("connect %s (%d online)", short(id), online)

	go c.writer(ctx, cancel)
	c.sendJSON(map[string]any{"t": "ready", "id": id})
	err = h.reader(ctx, c)

	close(c.done)
	h.mu.Lock()
	if h.conns[id] == c {
		delete(h.conns, id)
	}
	online = len(h.conns)
	h.mu.Unlock()
	h.logf("disconnect %s (%d online): %v", short(id), online, websocket.CloseStatus(err))
	ws.CloseNow()
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
	c.allow, c.tickets = allow, tickets
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

	h.mu.Lock()
	to := h.conns[hd.To]
	ok := to != nil && h.allowed(c.id, to, hd.Ticket)
	if ok && hd.Ticket != "" {
		h.replyPass[[2]string{to.id, c.id}] = h.now().Add(replyPassFor)
	}
	h.mu.Unlock()
	if to == nil {
		fail("offline")
		return
	}
	if !ok {
		fail("not_allowed")
		return
	}

	hd.From, hd.Ticket = c.id, ""
	head, _ := json.Marshal(hd)
	frame := make([]byte, 2, 2+len(head)+len(data)-2-n)
	binary.BigEndian.PutUint16(frame, uint16(len(head)))
	frame = append(append(frame, head...), data[2+n:]...)

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

// allowed says whether sender may reach to. Call with h.mu held.
func (h *Hub) allowed(sender string, to *conn, ticket string) bool {
	now := h.now()
	if to.allow[sender] {
		return true
	}
	if exp, ok := to.tickets[ticket]; ticket != "" && ok && now.Before(exp) {
		return true
	}
	if until, ok := h.replyPass[[2]string{sender, to.id}]; ok {
		if now.Before(until) {
			return true
		}
		delete(h.replyPass, [2]string{sender, to.id})
	}
	return false
}

func (c *conn) writer(ctx context.Context, cancel context.CancelFunc) {
	defer cancel()
	ping := time.NewTicker(pingEvery)
	defer ping.Stop()
	for {
		select {
		case f := <-c.out:
			wctx, wcancel := context.WithTimeout(ctx, sendTimeout)
			err := c.ws.Write(wctx, f.typ, f.data)
			wcancel()
			if err != nil {
				return
			}
		case <-ping.C:
			pctx, pcancel := context.WithTimeout(ctx, sendTimeout)
			err := c.ws.Ping(pctx)
			pcancel()
			if err != nil {
				return
			}
		case <-ctx.Done():
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
