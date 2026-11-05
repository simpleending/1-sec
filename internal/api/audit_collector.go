package api

import (
	"crypto/tls"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/1sec-project/1sec/internal/core"
)

// NewAuditCollectorServer exposes ingestion and a readiness check only. It does
// not start the event broker, detectors, response executors or management API.
func NewAuditCollectorServer(cfg *core.Config, receiver *core.AuditReceiver) *http.Server {
	s := &Server{engine: &core.Engine{Config: cfg, AuditReceiver: receiver}}
	base := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if !receiver.Ready() {
			writeError(w, 503, "audit_receiver_unavailable", "audit storage requires attention")
			return
		}
		writeJSON(w, 200, map[string]bool{"ready": true})
	})
	return &http.Server{Addr: net.JoinHostPort(cfg.Server.Host, strconv.Itoa(cfg.Server.Port)), Handler: rateLimitMiddleware(s.auditReceiverMiddleware(base), 100), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
}
