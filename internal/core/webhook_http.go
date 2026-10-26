package core

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

func newWebhookHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return &http.Client{
		Timeout:       15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("webhook redirects are disabled") },
		Transport: &http.Transport{
			TLSHandshakeTimeout: 5 * time.Second,
			IdleConnTimeout:     30 * time.Second,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialPublicWebhook(ctx, network, addr, net.DefaultResolver.LookupIPAddr, dialer.DialContext)
			},
		},
	}
}

func dialPublicWebhook(ctx context.Context, network, addr string, lookup func(context.Context, string) ([]net.IPAddr, error), dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("webhook destination has no addresses")
	}
	for _, ip := range ips {
		if !ip.IP.IsGlobalUnicast() || ip.IP.IsPrivate() || ip.IP.IsLinkLocalUnicast() || sharedAddressSpace.Contains(ip.IP) {
			return nil, fmt.Errorf("webhook destination is not a public address")
		}
	}
	var lastErr error
	for _, ip := range ips {
		conn, err := dial(ctx, network, net.JoinHostPort(ip.IP.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

var sharedAddressSpace = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}
