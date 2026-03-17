package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/charlieseay/stdout-scanner/internal/output"
)

type PushResult struct {
	ImportID  string `json:"importId"`
	ReviewURL string `json:"reviewUrl"`
}

func Push(baseURL, token string, scan output.ScanResult) (*PushResult, error) {
	baseURL = strings.TrimRight(baseURL, "/")
	endpoint := baseURL + "/app/api/stacks/import"

	body, err := json.Marshal(scan)
	if err != nil {
		return nil, fmt.Errorf("marshal scan: %w", err)
	}

	req, err := http.NewRequest("POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", "stdout-scanner/1.0")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != 201 && resp.StatusCode != 200 {
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result PushResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}

	return &result, nil
}
