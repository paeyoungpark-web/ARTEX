// Package kr provides the bridge between ARTEX's Go core and the Korean
// compliance sidecar (Python). It registers Korean-specific tools, prompts,
// and finding workflows into the ARTEX agent system so that ARTEX's Planner,
// Worker, and MainAgent can natively use Korean compliance features.
//
// Architecture: The heavy Python logic (SAST/DAST/judgment/report) runs as a
// sidecar HTTP service on :8800. This Go bridge proxies tool calls to it,
// translating between ARTEX's tool interface and the sidecar's REST API.
package kr

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// SidecarURL is the base URL of the Korean compliance sidecar service.
var SidecarURL = "http://localhost:8800"

// Client is a reusable HTTP client for sidecar communication.
var Client = &http.Client{Timeout: 120 * time.Second}

// callSidecar makes a JSON POST to the Python sidecar and returns the response body.
func callSidecar(ctx context.Context, path string, payload any) (json.RawMessage, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("kr: marshal error: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", SidecarURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("kr: request error: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kr: sidecar unreachable (%s): %w", SidecarURL+path, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("kr: sidecar error %d: %s", resp.StatusCode, string(respBody[:min(len(respBody), 200)]))
	}

	return json.RawMessage(respBody), nil
}

// getSidecar makes a GET request to the sidecar.
func getSidecar(ctx context.Context, path string) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", SidecarURL+path, nil)
	if err != nil {
		return nil, err
	}

	resp, err := Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kr: sidecar unreachable: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	return json.RawMessage(body), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
