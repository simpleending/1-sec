package main

// ---------------------------------------------------------------------------
// http.go — HTTP client helpers for API communication
// ---------------------------------------------------------------------------

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/1sec-project/1sec/internal/core"
)

func apiGet(url, apiKey string, timeout time.Duration) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	client := core.NewAuthenticatedHTTPClient(timeout)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connecting to 1SEC API at %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return body, fmt.Errorf("authentication failed (HTTP %d) — provide --api-key or set ONESEC_API_KEY", resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return body, fmt.Errorf("API returned HTTP %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

func apiPost(url string, payload []byte, apiKey string, timeout time.Duration) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	client := core.NewAuthenticatedHTTPClient(timeout)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connecting to 1SEC API at %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return body, fmt.Errorf("authentication failed (HTTP %d) — provide --api-key or set ONESEC_API_KEY", resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return body, fmt.Errorf("API returned HTTP %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

func apiPatch(url string, payload []byte, apiKey string, timeout time.Duration) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPatch, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	client := core.NewAuthenticatedHTTPClient(timeout)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connecting to 1SEC API at %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return body, fmt.Errorf("authentication failed (HTTP %d) — provide --api-key or set ONESEC_API_KEY", resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return body, fmt.Errorf("API returned HTTP %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

// apiDelete sends a DELETE request.
func apiDelete(url, apiKey string, timeout time.Duration) ([]byte, error) {
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	client := core.NewAuthenticatedHTTPClient(timeout)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connecting to 1SEC API at %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return body, fmt.Errorf("authentication failed (HTTP %d) — provide --api-key or set ONESEC_API_KEY", resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return body, fmt.Errorf("API returned HTTP %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}

// isConnectionError checks if an error is a transient connection issue.
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "connection reset") ||
		strings.Contains(s, "EOF") ||
		strings.Contains(s, "connection refused")
}

// doGet performs a GET request and returns the raw http.Response for streaming JSON decoding.
func doGet(url, apiKey string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	client := core.NewAuthenticatedHTTPClient(15 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connecting to 1SEC API at %s: %w", url, err)
	}
	return resp, nil
}

// doPost performs a POST request and returns the raw http.Response.
func doPost(url, apiKey string, payload []byte) (*http.Response, error) {
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}
	client := core.NewAuthenticatedHTTPClient(15 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connecting to 1SEC API at %s: %w", url, err)
	}
	return resp, nil
}
