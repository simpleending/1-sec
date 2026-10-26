package ingest

import (
	"context"
	"github.com/1sec-project/1sec/internal/core"
	"github.com/rs/zerolog"
	"net"
	"testing"
	"time"
)

func TestSyslogBoundsConnectionsIdleAndShutdown(t *testing.T) {
	s := NewSyslogServer(&core.SyslogConfig{Protocol: "tcp", Host: "127.0.0.1", Port: 0, MaxConnections: 1, ReadTimeoutSeconds: 1}, nil, zerolog.Nop())
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer s.Stop()
	connect := func() net.Conn {
		t.Helper()
		c, err := net.Dial("tcp", s.tcpLn.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	first := connect()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		n := len(s.connections)
		s.mu.Unlock()
		if n == 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	second := connect()
	second.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := second.Read(make([]byte, 1)); err == nil {
		t.Fatal("excess connection accepted")
	}
	first.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := first.Read(make([]byte, 1)); err == nil {
		t.Fatal("idle peer retained")
	}
	third := connect()
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	third.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := third.Read(make([]byte, 1)); err == nil {
		t.Fatal("peer not closed at shutdown")
	}
}
