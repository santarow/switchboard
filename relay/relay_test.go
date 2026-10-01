package relay

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

type device struct {
	t   *testing.T
	id  string
	ws  *websocket.Conn
	ctx context.Context
}

func dial(t *testing.T, srv *httptest.Server) *device {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	ws.SetReadLimit(maxFrame)
	t.Cleanup(func() { ws.CloseNow() })
	d := &device{t: t, id: b64.EncodeToString(pub), ws: ws, ctx: ctx}
	ch := d.readJSON()
	nonce, _ := b64.DecodeString(ch["nonce"].(string))
	host := strings.TrimPrefix(srv.URL, "http://")
	sig := ed25519.Sign(priv, LoginMessage(host, nonce))
	d.writeJSON(map[string]any{"t": "login", "id": d.id, "sig": b64.EncodeToString(sig)})
	if r := d.readJSON(); r["t"] != "ready" || r["id"] != d.id {
		t.Fatalf("login: %v", r)
	}
	return d
}

func (d *device) writeJSON(v any) {
	data, _ := json.Marshal(v)
	if err := d.ws.Write(d.ctx, websocket.MessageText, data); err != nil {
		d.t.Fatal(err)
	}
}

func (d *device) readJSON() map[string]any {
	typ, data, err := d.ws.Read(d.ctx)
	if err != nil || typ != websocket.MessageText {
		d.t.Fatalf("want text frame: %v", err)
	}
	var m map[string]any
	json.Unmarshal(data, &m)
	return m
}

func (d *device) send(h Header, payload []byte) {
	head, _ := json.Marshal(h)
	f := binary.BigEndian.AppendUint16(nil, uint16(len(head)))
	f = append(append(f, head...), payload...)
	if err := d.ws.Write(d.ctx, websocket.MessageBinary, f); err != nil {
		d.t.Fatal(err)
	}
}

func (d *device) recv() (Header, []byte) {
	typ, data, err := d.ws.Read(d.ctx)
	if err != nil {
		d.t.Fatal(err)
	}
	if typ != websocket.MessageBinary {
		d.t.Fatalf("want binary frame, got %s", data)
	}
	n := binary.BigEndian.Uint16(data)
	var h Header
	json.Unmarshal(data[2:2+n], &h)
	return h, data[2+n:]
}

func setup(t *testing.T) *httptest.Server {
	hub := NewHub()
	hub.logf = func(string, ...any) {}
	srv := httptest.NewServer(hub)
	t.Cleanup(srv.Close)
	return srv
}

// settle gives the relay a moment to apply a policy frame before the next send.
func settle() { time.Sleep(50 * time.Millisecond) }

func TestNotAllowedWithoutPolicy(t *testing.T) {
	srv := setup(t)
	mac, phone := dial(t, srv), dial(t, srv)
	phone.send(Header{To: mac.id, ID: "a"}, []byte("x"))
	if r := phone.readJSON(); r["error"] != "not_allowed" || r["re"] != "a" {
		t.Fatal(r)
	}
}

func TestOffline(t *testing.T) {
	srv := setup(t)
	phone := dial(t, srv)
	phone.send(Header{To: strings.Repeat("A", 43), ID: "a"}, []byte("x"))
	if r := phone.readJSON(); r["error"] != "offline" {
		t.Fatal(r)
	}
}

func TestAllowedForwardSetsFrom(t *testing.T) {
	srv := setup(t)
	mac, phone := dial(t, srv), dial(t, srv)
	mac.writeJSON(map[string]any{"t": "policy", "allow": []string{phone.id}})
	settle()
	// A lying From is overwritten with the logged-in key.
	phone.send(Header{To: mac.id, From: mac.id, ID: "a", Last: true}, []byte("sealed"))
	h, p := mac.recv()
	if h.From != phone.id || h.ID != "a" || !h.Last || string(p) != "sealed" {
		t.Fatalf("%+v %q", h, p)
	}
}

func TestTicketAndReplyPass(t *testing.T) {
	srv := setup(t)
	mac, phone := dial(t, srv), dial(t, srv)
	hash := strings.Repeat("ab", 32)
	mac.writeJSON(map[string]any{"t": "policy", "tickets": []map[string]any{{"hash": hash, "exp": time.Now().Add(time.Minute).Unix()}}})
	settle()

	phone.send(Header{To: mac.id, ID: "p", Ticket: strings.Repeat("cd", 32)}, nil)
	if r := phone.readJSON(); r["error"] != "not_allowed" {
		t.Fatal("wrong ticket let through", r)
	}
	phone.send(Header{To: mac.id, ID: "p", Ticket: hash, Key: "k"}, []byte("pair"))
	h, _ := mac.recv()
	if h.Ticket != "" || h.Key != "k" {
		t.Fatalf("ticket should be stripped, key kept: %+v", h)
	}
	// The Mac may answer the phone that brought a ticket, though nobody allowed it.
	mac.send(Header{To: phone.id, ID: "r"}, []byte("answer"))
	if h, p := phone.recv(); h.From != mac.id || string(p) != "answer" {
		t.Fatal(h, p)
	}
	// A stranger can't use the Mac's reply pass.
	other := dial(t, srv)
	mac.send(Header{To: other.id, ID: "s"}, nil)
	if r := mac.readJSON(); r["error"] != "not_allowed" {
		t.Fatal(r)
	}
}

func TestExpiredTicket(t *testing.T) {
	srv := setup(t)
	mac, phone := dial(t, srv), dial(t, srv)
	hash := strings.Repeat("ab", 32)
	mac.writeJSON(map[string]any{"t": "policy", "tickets": []map[string]any{{"hash": hash, "exp": time.Now().Add(-time.Second).Unix()}}})
	settle()
	phone.send(Header{To: mac.id, ID: "p", Ticket: hash}, nil)
	if r := phone.readJSON(); r["error"] != "not_allowed" {
		t.Fatal(r)
	}
}

func TestBadSignature(t *testing.T) {
	srv := setup(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	ws.Read(ctx)
	pub, _, _ := ed25519.GenerateKey(nil)
	data, _ := json.Marshal(map[string]any{"t": "login", "id": b64.EncodeToString(pub), "sig": b64.EncodeToString(make([]byte, 64))})
	ws.Write(ctx, websocket.MessageText, data)
	if _, _, err := ws.Read(ctx); websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatalf("want policy violation close, got %v", err)
	}
}

func TestTooBig(t *testing.T) {
	srv := setup(t)
	mac, phone := dial(t, srv), dial(t, srv)
	mac.writeJSON(map[string]any{"t": "policy", "allow": []string{phone.id}})
	settle()
	phone.send(Header{To: mac.id, ID: "a"}, make([]byte, maxPayload+1))
	if r := phone.readJSON(); r["error"] != "too_big" {
		t.Fatal(r)
	}
	phone.send(Header{To: mac.id, ID: "b"}, make([]byte, maxPayload))
	if _, p := mac.recv(); len(p) != maxPayload {
		t.Fatal(len(p))
	}
}
