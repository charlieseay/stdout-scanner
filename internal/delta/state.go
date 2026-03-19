package delta

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/charlieseay/stdout-scanner/internal/output"
)

// SaveState writes a scan result to disk for future delta comparison.
func SaveState(path string, scan output.ScanResult) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create state dir: %w", err)
	}

	data, err := json.Marshal(scan)
	if err != nil {
		return fmt.Errorf("marshal scan: %w", err)
	}

	return os.WriteFile(path, data, 0600)
}

// LoadState reads a previously saved scan result.
func LoadState(path string) (*output.ScanResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var scan output.ScanResult
	if err := json.Unmarshal(data, &scan); err != nil {
		return nil, fmt.Errorf("parse state: %w", err)
	}

	return &scan, nil
}
