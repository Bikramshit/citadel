package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"citadel/internal/evidence"
	"citadel/internal/harness"
)

func thresholdsEvidence(t harness.Thresholds) evidence.Thresholds {
	return evidence.Thresholds{K: t.K, MinFlows: t.MinFlows}
}

// postJSON posts body and decodes a bounded JSON response.
func postJSON(ctx context.Context, c *http.Client, url string, body []byte) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("post %s: %w", url, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("post %s: %w", url, err)
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("post %s: status %d: %s", url, resp.StatusCode, b)
	}
	return b, nil
}

// getJSON fetches url into v and returns the status code.
func getJSON(ctx context.Context, c *http.Client, url string, v any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	if resp.StatusCode == http.StatusOK && v != nil {
		if err := json.Unmarshal(b, v); err != nil {
			return resp.StatusCode, err
		}
	}
	return resp.StatusCode, nil
}

func digestHex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
