// Switchboard connects a phone to a computer that has no public address: both connect out to it,
// and it relays sealed frames between paired keys. It never holds a key that can open them.
// See AGENTS.md and docs/protocol.md.
package main

import (
	"flag"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/jasonjias/switchboard/relay"
)

var version = "dev"

func main() {
	addr := flag.String("addr", "127.0.0.1:8790", "listen address (cloudflared points here)")
	host := flag.String("host", "", "public host name clients sign their login for (e.g. switchboard.example); default: the request's Host header")
	stun := flag.String("stun", "", "STUN servers for direct calls, comma separated (e.g. stun:stun.cloudflare.com:3478)")
	flag.Parse()

	var ice []relay.ICEServer
	if *stun != "" {
		ice = append(ice, relay.ICEServer{URLs: strings.Split(*stun, ",")})
	}

	hub := relay.NewHub(ice...)
	hub.Host = *host
	mux := http.NewServeMux()
	mux.Handle("GET /v1/connect", hub)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true,"version":"` + version + `"}`))
	})

	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Printf("switchboard %s on %s", version, *addr)
	log.Fatal(srv.ListenAndServe())
}
