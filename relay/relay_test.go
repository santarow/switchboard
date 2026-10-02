package relay

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"fmt"
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

// Only a sender the recipient allows learns that it is offline; everyone else hears not_allowed,
// whether the recipient is online, offline, or never seen.
func TestOfflineOnlyForAllowed(t *testing.T) {
	srv := setup(t)
	mac, phone, stranger := dial(t, srv), dial(t, srv), dial(t, srv)
	mac.writeJSON(map[string]any{"t": "policy", "allow": []string{phone.id}})
	settle()
	stranger.send(Header{To: mac.id, ID: "a"}, nil)
	if r := stranger.readJSON(); r["error"] != "not_allowed" {
		t.Fatal("stranger, Mac online:", r)
	}
	mac.ws.Close(websocket.StatusNormalClosure, "")
	settle()
	phone.send(Header{To: mac.id, ID: "b"}, nil)
	if r := phone.readJSON(); r["error"] != "offline" || r["re"] != "b" {
		t.Fatal("paired phone, Mac offline:", r)
	}
	stranger.send(Header{To: mac.id, ID: "c"}, nil)
	if r := stranger.readJSON(); r["error"] != "not_allowed" {
		t.Fatal("stranger, Mac offline:", r)
	}
	stranger.send(Header{To: strings.Repeat("A", 43), ID: "d"}, nil)
	if r := stranger.readJSON(); r["error"] != "not_allowed" {
		t.Fatal("never seen:", r)
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

func TestReadyListsICE(t *testing.T) {
	hub := NewHub(ICEServer{URLs: []string{"stun:stun.example:3478"}})
	hub.logf = func(string, ...any) {}
	srv := httptest.NewServer(hub)
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ws.CloseNow()
	pub, priv, _ := ed25519.GenerateKey(nil)
	_, data, _ := ws.Read(ctx)
	var ch map[string]string
	json.Unmarshal(data, &ch)
	nonce, _ := b64.DecodeString(ch["nonce"])
	login, _ := json.Marshal(map[string]string{"t": "login", "id": b64.EncodeToString(pub),
		"sig": b64.EncodeToString(ed25519.Sign(priv, LoginMessage(strings.TrimPrefix(srv.URL, "http://"), nonce)))})
	ws.Write(ctx, websocket.MessageText, login)
	_, data, _ = ws.Read(ctx)
	if !strings.Contains(string(data), `"ice":[{"urls":["stun:stun.example:3478"]}]`) {
		t.Fatalf("%s", data)
	}
}

// A lossy frame for a recipient that is behind is dropped at once: no waiting, no error.
func TestLossyDropsWhenBehind(t *testing.T) {
	hub := NewHub()
	from := &conn{id: "from", out: make(chan outFrame, 8), done: make(chan struct{})}
	to := &conn{id: "to", out: make(chan outFrame), live: make(chan outFrame, 1), done: make(chan struct{}),
		pol: policy{allow: map[string]bool{"from": true}}}
	hub.conns["to"] = to
	frame := func() []byte {
		head, _ := json.Marshal(Header{To: "to", ID: "m", Last: true, Lossy: true})
		return append(binary.BigEndian.AppendUint16(nil, uint16(len(head))), append(head, "opus"...)...)
	}
	start := time.Now()
	for range 3 {
		hub.forward(context.Background(), from, frame())
	}
	if time.Since(start) > time.Second {
		t.Fatal("lossy send waited on a full queue")
	}
	if len(to.live) != 1 || len(from.out) != 0 {
		t.Fatalf("queued %d, errors %d", len(to.live), len(from.out))
	}
}

// Live frames go ahead of a backlog of ordinary ones.
func TestLiveGoesFirst(t *testing.T) {
	srv := setup(t)
	mac, phone := dial(t, srv), dial(t, srv)
	mac.writeJSON(map[string]any{"t": "policy", "allow": []string{phone.id}})
	settle()
	for i := range 20 {
		phone.send(Header{To: mac.id, ID: fmt.Sprint("bulk", i), Last: true}, make([]byte, maxPayload))
	}
	phone.send(Header{To: mac.id, ID: "audio", Last: true, Lossy: true}, []byte("opus"))
	seen := 0
	for range 21 {
		h, _ := mac.recv()
		if h.ID == "audio" {
			if seen == 20 {
				t.Fatal("audio came last, behind all the bulk frames")
			}
			return
		}
		seen++
	}
	t.Fatal("audio never arrived")
}

// With Host pinned, a login signed for the host name the client happened to use is refused.
func TestPinnedHost(t *testing.T) {
	hub := NewHub()
	hub.logf = func(string, ...any) {}
	hub.Host = "switchboard.example"
	srv := httptest.NewServer(hub)
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	login := func(host string) error {
		ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer ws.CloseNow()
		pub, priv, _ := ed25519.GenerateKey(nil)
		_, data, _ := ws.Read(ctx)
		var ch map[string]string
		json.Unmarshal(data, &ch)
		nonce, _ := b64.DecodeString(ch["nonce"])
		msg, _ := json.Marshal(map[string]string{"t": "login", "id": b64.EncodeToString(pub),
			"sig": b64.EncodeToString(ed25519.Sign(priv, LoginMessage(host, nonce)))})
		ws.Write(ctx, websocket.MessageText, msg)
		_, _, err = ws.Read(ctx)
		return err
	}
	if err := login(strings.TrimPrefix(srv.URL, "http://")); websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatalf("login for the dialed host should fail when Host is pinned: %v", err)
	}
	if err := login("switchboard.example"); err != nil {
		t.Fatalf("login for the pinned host: %v", err)
	}
}

// A live audio frame must be small; a big one is refused rather than queued ahead of everything.
func TestLossyTooBig(t *testing.T) {
	srv := setup(t)
	mac, phone := dial(t, srv), dial(t, srv)
	mac.writeJSON(map[string]any{"t": "policy", "allow": []string{phone.id}})
	settle()
	phone.send(Header{To: mac.id, ID: "a", Last: true, Lossy: true}, make([]byte, maxLossy+1))
	if r := phone.readJSON(); r["error"] != "too_big" || r["re"] != "a" {
		t.Fatal(r)
	}
}

// A second login with the same key replaces the first, and the hub keeps relaying meanwhile.
func TestReplaceDoesNotBlock(t *testing.T) {
	hub := NewHub()
	hub.logf = func(string, ...any) {}
	srv := httptest.NewServer(hub)
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pub, priv, _ := ed25519.GenerateKey(nil)
	connect := func() *websocket.Conn {
		ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil)
		if err != nil {
			t.Fatal(err)
		}
		_, data, _ := ws.Read(ctx)
		var ch map[string]string
		json.Unmarshal(data, &ch)
		nonce, _ := b64.DecodeString(ch["nonce"])
		msg, _ := json.Marshal(map[string]string{"t": "login", "id": b64.EncodeToString(pub),
			"sig": b64.EncodeToString(ed25519.Sign(priv, LoginMessage(strings.TrimPrefix(srv.URL, "http://"), nonce)))})
		ws.Write(ctx, websocket.MessageText, msg)
		if _, data, err := ws.Read(ctx); err != nil || !strings.Contains(string(data), `"ready"`) {
			t.Fatalf("login: %s %v", data, err)
		}
		return ws
	}
	first := connect() // never reads again, so it won't answer the close handshake
	defer first.CloseNow()
	start := time.Now()
	second := connect()
	defer second.CloseNow()
	other := dial(t, srv)
	other.send(Header{To: strings.Repeat("A", 43), ID: "x"}, nil)
	if r := other.readJSON(); r["error"] != "not_allowed" {
		t.Fatal(r)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("the hub stalled while closing the replaced connection")
	}
}

func TestConnectionLimits(t *testing.T) {
	hub := NewHub()
	hub.logf = func(string, ...any) {}
	hub.MaxConns, hub.MaxConnsPerIP = 3, 2
	srv := httptest.NewServer(hub)
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	open := func(from string) (int, *websocket.Conn) {
		var opts websocket.DialOptions
		if from != "" {
			opts.HTTPHeader = map[string][]string{"CF-Connecting-IP": {from}}
		}
		ws, resp, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), &opts)
		if err != nil {
			return resp.StatusCode, nil
		}
		t.Cleanup(func() { ws.CloseNow() })
		return 101, ws
	}
	// From loopback the proxy's header names the client, so two addresses get two slots each.
	var first *websocket.Conn
	for i, want := range []struct {
		from   string
		status int
	}{{"192.0.2.1", 101}, {"192.0.2.1", 101}, {"192.0.2.1", 429}, {"192.0.2.2", 101}, {"192.0.2.3", 503}} {
		got, ws := open(want.from)
		if got != want.status {
			t.Fatalf("from %s: got %d, want %d", want.from, got, want.status)
		}
		if i == 0 {
			first = ws
		}
	}
	// A closed connection gives its slot back.
	first.CloseNow()
	for range 50 {
		if got, _ := open("192.0.2.1"); got == 101 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("slot never came back after a close")
}

func TestIPHeaderOnlyFromLoopback(t *testing.T) {
	hub := NewHub()
	r := httptest.NewRequest("GET", "/v1/connect", nil)
	r.Header.Set("CF-Connecting-IP", "192.0.2.9")
	r.RemoteAddr = "198.51.100.7:4000"
	if ip := hub.clientIP(r); ip != "198.51.100.7" {
		t.Fatal("trusted the header from a remote peer:", ip)
	}
	r.RemoteAddr = "127.0.0.1:4000"
	if ip := hub.clientIP(r); ip != "192.0.2.9" {
		t.Fatal("ignored the header from cloudflared:", ip)
	}
}

func TestPolicyTooBig(t *testing.T) {
	srv := setup(t)
	mac, phone := dial(t, srv), dial(t, srv)
	mac.writeJSON(map[string]any{"t": "policy", "allow": []string{phone.id}})
	big := make([]string, maxAllow+1)
	for i := range big {
		big[i] = phone.id
	}
	mac.writeJSON(map[string]any{"t": "policy", "allow": big})
	if r := mac.readJSON(); r["error"] != "too_big" {
		t.Fatal(r)
	}
	// The previous policy stays.
	phone.send(Header{To: mac.id, ID: "a", Last: true}, []byte("x"))
	if h, _ := mac.recv(); h.From != phone.id {
		t.Fatal(h)
	}
}

func TestGoneKeepsNewest(t *testing.T) {
	hub := NewHub()
	at := time.Unix(0, 0)
	hub.now = func() time.Time { return at }
	for i := range maxGone + 1 {
		at = at.Add(time.Second)
		hub.remember(fmt.Sprint(i), policy{})
	}
	if _, ok := hub.gone["0"]; ok || len(hub.gone) != maxGone {
		t.Fatalf("kept %d, oldest still there: %v", len(hub.gone), ok)
	}
}
