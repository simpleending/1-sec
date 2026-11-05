package main

import (
	"context"
	"errors"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/1sec-project/1sec/internal/api"
	"github.com/1sec-project/1sec/internal/core"
)

func cmdAuditCollector(args []string) {
	fs := flag.NewFlagSet("audit-collector", flag.ExitOnError)
	path := fs.String("config", "configs/default.yaml", "Private collector configuration file")
	fs.Parse(args)
	cfg, err := core.LoadConfig(*path)
	if err != nil {
		errorf("load collector configuration: %v", err)
	}
	if !cfg.AuditReceiver.Enabled || !cfg.TLSEnabled() {
		errorf("audit-collector requires audit_receiver.enabled and server.tls_cert/tls_key")
	}
	if cfg.Server.Port <= 0 || cfg.Server.Port > 65535 {
		errorf("invalid collector port")
	}
	receiver, err := core.NewAuditReceiver(cfg.AuditReceiver)
	if err != nil {
		errorf("load audit receiver: %v", err)
	}
	defer receiver.Close()
	server := api.NewAuditCollectorServer(cfg, receiver)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	served := make(chan error, 1)
	go func() { served <- server.ListenAndServeTLS(cfg.Server.TLSCert, cfg.Server.TLSKey) }()
	select {
	case err := <-served:
		if !errors.Is(err, http.ErrServerClosed) {
			errorf("audit collector stopped: %v", err)
		}
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			_ = server.Close()
			errorf("audit collector shutdown: %v", err)
		}
	}
}
