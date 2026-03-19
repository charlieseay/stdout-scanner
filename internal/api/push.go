package api

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/charlieseay/stdout-scanner/internal/output"
)

// PushResult holds the response from any target.
type PushResult struct {
	// StdOut-specific fields (populated when target is StdOut)
	ImportID  string `json:"importId,omitempty"`
	ReviewURL string `json:"reviewUrl,omitempty"`

	// Generic fields
	StatusCode int    `json:"statusCode"`
	Body       string `json:"body,omitempty"`
}

// Target describes where to send scan results.
type Target struct {
	URL      string            // Full URL to POST to
	Token    string            // Bearer token (optional)
	Headers  map[string]string // Additional headers (optional)
	Insecure bool              // Skip TLS verification
}

// StdOutTarget creates a target configured for StdOut's import endpoint.
func StdOutTarget(baseURL, token string) Target {
	return Target{
		URL:   strings.TrimRight(baseURL, "/") + "/app/api/stacks/import",
		Token: token,
	}
}

// WebhookTarget creates a generic webhook target.
func WebhookTarget(url string, token string, headers map[string]string) Target {
	return Target{
		URL:     url,
		Token:   token,
		Headers: headers,
	}
}

// Push sends scan results to a target URL via HTTP POST.
// Works with StdOut, generic webhooks, or any endpoint that accepts JSON.
func Push(target Target, scan output.ScanResult) (*PushResult, error) {
	body, err := json.Marshal(scan)
	if err != nil {
		return nil, fmt.Errorf("marshal scan: %w", err)
	}

	req, err := http.NewRequest("POST", target.URL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "stdout-scanner/2.0")

	if target.Token != "" {
		req.Header.Set("Authorization", "Bearer "+target.Token)
	}

	for k, v := range target.Headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	if target.Insecure {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(respBody))
	}

	result := &PushResult{
		StatusCode: resp.StatusCode,
		Body:       string(respBody),
	}

	// Try to parse StdOut-style response (importId/reviewUrl)
	json.Unmarshal(respBody, result)

	return result, nil
}

// PushToFile saves scan results to a JSON file.
func PushToFile(path string, scan output.ScanResult) error {
	data, err := json.MarshalIndent(scan, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal scan: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// Legacy Push function for backward compatibility.
// Deprecated: Use Push(StdOutTarget(url, token), scan) instead.
func PushToStdOut(baseURL, token string, scan output.ScanResult) (*PushResult, error) {
	return Push(StdOutTarget(baseURL, token), scan)
}
