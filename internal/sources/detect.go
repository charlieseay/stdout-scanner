package sources

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/charlieseay/stdout-scanner/internal/docker"
)

// SourceType categorizes what kind of data a tool provides.
type SourceType string

const (
	SourceCVE     SourceType = "cve"
	SourceMetrics SourceType = "metrics"
	SourceUptime  SourceType = "uptime"
	SourceLogs    SourceType = "logs"
	SourceVuln    SourceType = "vuln"
	SourceNetSec  SourceType = "netsec"
)

// DetectionMethod describes how a source was found.
type DetectionMethod string

const (
	DetectedViaDocker    DetectionMethod = "docker_container"
	DetectedViaPort      DetectionMethod = "port_probe"
	DetectedViaBinary    DetectionMethod = "binary_in_path"
	DetectedViaConfig    DetectionMethod = "config_file"
)

// DataSource represents a detected (or missing) infrastructure tool.
type DataSource struct {
	Name        string          `json:"name"`
	Type        SourceType      `json:"type"`
	DetectedVia DetectionMethod `json:"detected_via"`
	Endpoint    string          `json:"endpoint"`
	Status      string          `json:"status"`      // running, stopped, accessible, unreachable
	Accessible  bool            `json:"accessible"`
	Version     string          `json:"version,omitempty"`
}

// MissingSource represents a data type with no detected tool.
type MissingSource struct {
	Type           SourceType `json:"type"`
	Recommendation string     `json:"recommendation"`
	Reason         string     `json:"reason"`
}

// SourcesResult is the top-level output of the sources module.
type SourcesResult struct {
	Detected []DataSource    `json:"detected,omitempty"`
	Missing  []MissingSource `json:"missing,omitempty"`
}

// toolDef defines a tool to look for during detection.
type toolDef struct {
	name        string
	sourceType  SourceType
	images      []string   // Docker image name substrings
	port        uint16     // default port to probe
	probePath   string     // HTTP path to confirm the service
	binaries    []string   // binary names to check in PATH
	configPaths []string   // config dirs/files to check
	endpoint    string     // default endpoint format (use %s for host)
}

// knownTools is the registry of tools the sources module can detect.
var knownTools = []toolDef{
	// Security / CVE
	{
		name:       "trivy",
		sourceType: SourceCVE,
		images:     []string{"aquasec/trivy", "ghcr.io/aquasecurity/trivy"},
		binaries:   []string{"trivy"},
		endpoint:   "trivy://local",
	},
	{
		name:       "grype",
		sourceType: SourceCVE,
		images:     []string{"anchore/grype"},
		binaries:   []string{"grype"},
		endpoint:   "grype://local",
	},

	// Metrics
	{
		name:        "prometheus",
		sourceType:  SourceMetrics,
		images:      []string{"prom/prometheus", "prometheus/prometheus"},
		port:        9090,
		probePath:   "/-/healthy",
		configPaths: []string{"/etc/prometheus/", "/etc/prometheus/prometheus.yml"},
		endpoint:    "http://%s:9090",
	},
	{
		name:       "grafana",
		sourceType: SourceMetrics,
		images:     []string{"grafana/grafana"},
		port:       3000,
		probePath:  "/api/health",
		endpoint:   "http://%s:3000",
	},
	{
		name:       "netdata",
		sourceType: SourceMetrics,
		images:     []string{"netdata/netdata"},
		port:       19999,
		probePath:  "/api/v1/info",
		endpoint:   "http://%s:19999",
	},
	{
		name:       "node_exporter",
		sourceType: SourceMetrics,
		images:     []string{"prom/node-exporter", "quay.io/prometheus/node-exporter"},
		port:       9100,
		probePath:  "/metrics",
		binaries:   []string{"node_exporter"},
		endpoint:   "http://%s:9100",
	},
	{
		name:       "cadvisor",
		sourceType: SourceMetrics,
		images:     []string{"gcr.io/cadvisor/cadvisor", "google/cadvisor"},
		port:       8080,
		probePath:  "/api/v1.0/machine",
		endpoint:   "http://%s:8080",
	},

	// Uptime / Health
	{
		name:       "uptime-kuma",
		sourceType: SourceUptime,
		images:     []string{"louislam/uptime-kuma"},
		port:       3001,
		probePath:  "/api/status-page/heartbeat",
		endpoint:   "http://%s:3001",
	},
	{
		name:       "gatus",
		sourceType: SourceUptime,
		images:     []string{"twinproduction/gatus"},
		port:       8080,
		probePath:  "/api/v1/endpoints/statuses",
		endpoint:   "http://%s:8080",
	},

	// Logs
	{
		name:       "loki",
		sourceType: SourceLogs,
		images:     []string{"grafana/loki"},
		port:       3100,
		probePath:  "/ready",
		endpoint:   "http://%s:3100",
	},
	{
		name:       "graylog",
		sourceType: SourceLogs,
		images:     []string{"graylog/graylog"},
		port:       9000,
		probePath:  "/api/system",
		endpoint:   "http://%s:9000",
	},
	{
		name:       "seq",
		sourceType: SourceLogs,
		images:     []string{"datalust/seq"},
		port:       5341,
		probePath:  "/api",
		endpoint:   "http://%s:5341",
	},

	// Vulnerability / Compliance
	{
		name:        "lynis",
		sourceType:  SourceVuln,
		binaries:    []string{"lynis"},
		configPaths: []string{"/etc/lynis/"},
		endpoint:    "lynis://local",
	},

	// Network Security
	{
		name:       "crowdsec",
		sourceType: SourceNetSec,
		images:     []string{"crowdsecurity/crowdsec"},
		port:       8080,
		probePath:  "/v1/decisions",
		binaries:   []string{"cscli"},
		endpoint:   "http://%s:8080",
	},
	{
		name:       "pihole",
		sourceType: SourceNetSec,
		images:     []string{"pihole/pihole"},
		port:       80,
		probePath:  "/admin/api.php",
		endpoint:   "http://%s:80",
	},
	{
		name:       "adguard-home",
		sourceType: SourceNetSec,
		images:     []string{"adguard/adguardhome"},
		port:       3000,
		probePath:  "/control/status",
		endpoint:   "http://%s:3000",
	},
	{
		name:       "suricata",
		sourceType: SourceNetSec,
		images:     []string{"jasonish/suricata"},
		binaries:   []string{"suricata"},
		endpoint:   "suricata://local",
	},
}

// Detect runs the full data source detection pipeline.
// It uses Docker container data (if available) and probes ports
// and the filesystem to find installed tools.
func Detect(containers []docker.Container) *SourcesResult {
	result := &SourcesResult{}

	// Build a lookup of running container images
	containerImages := make(map[string]docker.Container)
	for _, c := range containers {
		img := strings.ToLower(c.Image)
		containerImages[img] = c
		// Also index by image name without tag
		if idx := strings.LastIndex(img, ":"); idx != -1 {
			containerImages[img[:idx]] = c
		}
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for _, tool := range knownTools {
		wg.Add(1)
		go func(t toolDef) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			source := detectTool(t, containerImages)
			if source != nil {
				mu.Lock()
				result.Detected = append(result.Detected, *source)
				mu.Unlock()
			}
		}(tool)
	}
	wg.Wait()

	// Build the missing sources list
	result.Missing = findMissing(result.Detected)

	return result
}

// detectTool attempts to find a single tool using all available methods.
// Returns nil if the tool is not found by any method.
func detectTool(t toolDef, containerImages map[string]docker.Container) *DataSource {
	// Strategy 1: Docker container by image name
	for _, img := range t.images {
		imgLower := strings.ToLower(img)
		for ciImg, container := range containerImages {
			if strings.Contains(ciImg, imgLower) {
				source := &DataSource{
					Name:        t.name,
					Type:        t.sourceType,
					DetectedVia: DetectedViaDocker,
					Status:      container.Status,
				}

				// Build endpoint from container's published port or default
				source.Endpoint = buildEndpoint(t, container)

				// Extract version from image tag
				if idx := strings.LastIndex(container.Image, ":"); idx != -1 {
					tag := container.Image[idx+1:]
					if tag != "latest" && tag != "" {
						source.Version = tag
					}
				}

				// Probe the endpoint to confirm accessibility
				if t.port > 0 {
					source.Accessible = probeEndpoint(source.Endpoint, t.probePath)
				} else {
					source.Accessible = container.Status == "running"
				}

				fmt.Fprintf(os.Stderr, "  Source: %s (%s) via Docker [%s]\n", t.name, t.sourceType, container.Status)
				return source
			}
		}
	}

	// Strategy 2: Port probe (only for tools with known ports)
	if t.port > 0 {
		host := detectHost()
		if isPortOpen(host, t.port) {
			endpoint := fmt.Sprintf(t.endpoint, host)
			accessible := probeEndpoint(endpoint, t.probePath)
			if accessible {
				source := &DataSource{
					Name:        t.name,
					Type:        t.sourceType,
					DetectedVia: DetectedViaPort,
					Endpoint:    endpoint,
					Status:      "running",
					Accessible:  true,
				}
				// Try to get version from the probe response
				source.Version = probeVersion(endpoint, t)
				fmt.Fprintf(os.Stderr, "  Source: %s (%s) via port %d\n", t.name, t.sourceType, t.port)
				return source
			}
		}
	}

	// Strategy 3: Binary in PATH
	for _, bin := range t.binaries {
		if path, err := exec.LookPath(bin); err == nil {
			source := &DataSource{
				Name:        t.name,
				Type:        t.sourceType,
				DetectedVia: DetectedViaBinary,
				Endpoint:    t.endpoint,
				Status:      "installed",
				Accessible:  true,
			}
			// Try to get version from the binary
			source.Version = getBinaryVersion(path, bin)
			if source.Endpoint == "" {
				source.Endpoint = fmt.Sprintf("%s://local", t.name)
			}
			fmt.Fprintf(os.Stderr, "  Source: %s (%s) via binary at %s\n", t.name, t.sourceType, path)
			return source
		}
	}

	// Strategy 4: Config file presence
	for _, cfgPath := range t.configPaths {
		if _, err := os.Stat(cfgPath); err == nil {
			source := &DataSource{
				Name:        t.name,
				Type:        t.sourceType,
				DetectedVia: DetectedViaConfig,
				Endpoint:    t.endpoint,
				Status:      "configured",
				Accessible:  false, // config found but service might not be running
			}
			if source.Endpoint == "" {
				source.Endpoint = fmt.Sprintf("%s://local", t.name)
			}
			fmt.Fprintf(os.Stderr, "  Source: %s (%s) via config at %s\n", t.name, t.sourceType, cfgPath)
			return source
		}
	}

	return nil
}

// buildEndpoint constructs the endpoint URL from container port mappings or defaults.
func buildEndpoint(t toolDef, container docker.Container) string {
	host := detectHost()

	// Check if the container has a published port matching the tool's default
	for _, p := range container.Ports {
		if p.Container == t.port && p.Host > 0 {
			return fmt.Sprintf("http://%s:%d", host, p.Host)
		}
	}

	// Fall back to tool's default endpoint
	if t.port > 0 && strings.Contains(t.endpoint, "%s") {
		return fmt.Sprintf(t.endpoint, host)
	}

	return t.endpoint
}

// detectHost returns the host address to use for probing.
// Inside Docker it's host.docker.internal; otherwise localhost.
func detectHost() string {
	// Check if we're running inside Docker
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "host.docker.internal"
	}
	return "localhost"
}

// isPortOpen does a quick TCP connect to check if a port is open.
func isPortOpen(host string, port uint16) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// probeEndpoint does an HTTP GET to confirm a service is responding.
func probeEndpoint(baseURL, path string) bool {
	if path == "" {
		return false
	}

	url := strings.TrimRight(baseURL, "/") + path

	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "stdout-scanner/2.0")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	// Consider anything that responds (even 401/403) as accessible —
	// the service is there, it may just need auth.
	return resp.StatusCode < 500
}

// probeVersion attempts to extract a version string from a tool's API.
func probeVersion(baseURL string, t toolDef) string {
	// Tool-specific version endpoints
	versionEndpoints := map[string]string{
		"prometheus": "/api/v1/status/buildinfo",
		"grafana":    "/api/health",
		"loki":       "/loki/api/v1/status/buildinfo",
		"netdata":    "/api/v1/info",
	}

	path, ok := versionEndpoints[t.name]
	if !ok {
		return ""
	}

	url := strings.TrimRight(baseURL, "/") + path

	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return ""
	}

	// Try to extract version from JSON response
	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return ""
	}

	// Prometheus: {"data":{"version":"2.x"}}
	if d, ok := data["data"].(map[string]interface{}); ok {
		if v, ok := d["version"].(string); ok {
			return v
		}
	}

	// Grafana: {"version":"11.x"}
	if v, ok := data["version"].(string); ok {
		return v
	}

	return ""
}

// getBinaryVersion tries to run the binary with --version and extract the version.
func getBinaryVersion(path, name string) string {
	// Common version flags to try
	for _, flag := range []string{"--version", "version", "-v"} {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		out, err := exec.CommandContext(ctx, path, flag).CombinedOutput()
		cancel()
		if err != nil {
			continue
		}

		output := strings.TrimSpace(string(out))
		if output == "" {
			continue
		}

		// Extract version number from output
		// Common patterns: "trivy 0.49.1", "Version: 0.49.1", "grype 0.74.1"
		for _, line := range strings.Split(output, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			// Try to find a version-like pattern (digits.digits.digits)
			fields := strings.Fields(line)
			for _, f := range fields {
				f = strings.TrimPrefix(f, "v")
				if isVersionString(f) {
					return f
				}
			}
		}
	}
	return ""
}

// isVersionString checks if a string looks like a semantic version (e.g., "1.2.3").
func isVersionString(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) < 2 || len(parts) > 4 {
		return false
	}
	for _, part := range parts {
		// Allow digits and pre-release suffixes
		p := strings.Split(part, "-")[0]
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// findMissing determines which source types have no detected tool
// and generates recommendations.
func findMissing(detected []DataSource) []MissingSource {
	// Track which source types have at least one detection
	covered := make(map[SourceType]bool)
	for _, d := range detected {
		covered[d.Type] = true
	}

	recommendations := map[SourceType]MissingSource{
		SourceCVE: {
			Type:           SourceCVE,
			Recommendation: "trivy",
			Reason:         "No CVE scanner detected. Trivy is the simplest Docker-native option.",
		},
		SourceMetrics: {
			Type:           SourceMetrics,
			Recommendation: "prometheus",
			Reason:         "No metrics tool detected. Prometheus + node_exporter provides full host and container metrics.",
		},
		SourceLogs: {
			Type:           SourceLogs,
			Recommendation: "loki",
			Reason:         "No log aggregation tool detected. Loki + Promtail is lightweight and Docker-native.",
		},
		SourceVuln: {
			Type:           SourceVuln,
			Recommendation: "trivy",
			Reason:         "No vulnerability/compliance scanner detected. Trivy covers both image and OS scanning.",
		},
		SourceNetSec: {
			Type:           SourceNetSec,
			Recommendation: "crowdsec",
			Reason:         "No network security tool detected. CrowdSec provides IPS with community threat intelligence.",
		},
		// SourceUptime intentionally omitted — StdOut's HUD already covers this
	}

	var missing []MissingSource
	for sourceType, rec := range recommendations {
		if !covered[sourceType] {
			missing = append(missing, rec)
		}
	}

	return missing
}
