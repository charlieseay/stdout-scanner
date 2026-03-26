package sources

import (
	"testing"

	"github.com/charlieseay/stdout-scanner/internal/docker"
)

func TestIsVersionString(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"1.2.3", true},
		{"0.49.1", true},
		{"11.0", true},
		{"2.45.1-rc1", true},
		{"latest", false},
		{"", false},
		{"abc", false},
		{"1", false},
		{"v1.2.3", false}, // 'v' prefix should be stripped before calling
		{"1.2.3.4", true},
		{"1.2.3.4.5", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isVersionString(tt.input)
			if got != tt.want {
				t.Errorf("isVersionString(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestFindMissing(t *testing.T) {
	// No detected sources — all types should be missing
	missing := findMissing(nil)
	if len(missing) != 5 {
		t.Errorf("findMissing(nil) returned %d missing, want 5", len(missing))
	}

	// Uptime should never appear in missing (StdOut HUD covers it)
	for _, m := range missing {
		if m.Type == SourceUptime {
			t.Errorf("findMissing should not recommend uptime tools (StdOut HUD covers this)")
		}
	}
}

func TestFindMissingWithDetections(t *testing.T) {
	detected := []DataSource{
		{Name: "trivy", Type: SourceCVE},
		{Name: "prometheus", Type: SourceMetrics},
		{Name: "loki", Type: SourceLogs},
	}

	missing := findMissing(detected)

	// Should only be missing vuln and netsec
	missingTypes := make(map[SourceType]bool)
	for _, m := range missing {
		missingTypes[m.Type] = true
	}

	if missingTypes[SourceCVE] {
		t.Error("CVE should not be missing (trivy detected)")
	}
	if missingTypes[SourceMetrics] {
		t.Error("Metrics should not be missing (prometheus detected)")
	}
	if missingTypes[SourceLogs] {
		t.Error("Logs should not be missing (loki detected)")
	}
	if !missingTypes[SourceVuln] {
		t.Error("Vuln should be missing (nothing detected)")
	}
	if !missingTypes[SourceNetSec] {
		t.Error("NetSec should be missing (nothing detected)")
	}
}

func TestFindMissingAllCovered(t *testing.T) {
	detected := []DataSource{
		{Name: "trivy", Type: SourceCVE},
		{Name: "prometheus", Type: SourceMetrics},
		{Name: "loki", Type: SourceLogs},
		{Name: "lynis", Type: SourceVuln},
		{Name: "crowdsec", Type: SourceNetSec},
	}

	missing := findMissing(detected)
	if len(missing) != 0 {
		t.Errorf("findMissing with all types covered returned %d missing, want 0", len(missing))
	}
}

func TestDetectToolDockerMatch(t *testing.T) {
	containers := map[string]docker.Container{
		"prom/prometheus:2.51.0": {
			Name:   "prometheus",
			Image:  "prom/prometheus:2.51.0",
			Status: "running",
			Ports: []docker.Port{
				{Host: 9090, Container: 9090, Protocol: "tcp"},
			},
		},
	}

	tool := toolDef{
		name:       "prometheus",
		sourceType: SourceMetrics,
		images:     []string{"prom/prometheus"},
		port:       9090,
		probePath:  "/-/healthy",
		endpoint:   "http://%s:9090",
	}

	source := detectToolDocker(tool, containers)
	if source == nil {
		t.Fatal("detectTool returned nil for matching Docker container")
	}
	if source.Name != "prometheus" {
		t.Errorf("source.Name = %q, want %q", source.Name, "prometheus")
	}
	if source.Type != SourceMetrics {
		t.Errorf("source.Type = %q, want %q", source.Type, SourceMetrics)
	}
	if source.DetectedVia != DetectedViaDocker {
		t.Errorf("source.DetectedVia = %q, want %q", source.DetectedVia, DetectedViaDocker)
	}
	if source.Version != "2.51.0" {
		t.Errorf("source.Version = %q, want %q", source.Version, "2.51.0")
	}
	if source.Status != "running" {
		t.Errorf("source.Status = %q, want %q", source.Status, "running")
	}
}

func TestDetectToolDockerNoMatch(t *testing.T) {
	containers := map[string]docker.Container{
		"nginx:latest": {
			Name:   "nginx",
			Image:  "nginx:latest",
			Status: "running",
		},
	}

	tool := toolDef{
		name:       "trivy",
		sourceType: SourceCVE,
		images:     []string{"aquasec/trivy"},
		binaries:   []string{"trivy"},
		endpoint:   "trivy://local",
	}

	// This should not match via Docker (no trivy container).
	// It also won't match via binary/config on this test system.
	// The tool may or may not be in PATH — so we just verify Docker didn't match.
	source := detectToolDocker(tool, containers)
	if source != nil && source.DetectedVia == DetectedViaDocker {
		t.Error("detectTool should not have matched trivy via Docker with only nginx container")
	}
}

func TestDetectToolVersionFromLatestTag(t *testing.T) {
	containers := map[string]docker.Container{
		"grafana/grafana:latest": {
			Name:   "grafana",
			Image:  "grafana/grafana:latest",
			Status: "running",
			Ports: []docker.Port{
				{Host: 3000, Container: 3000, Protocol: "tcp"},
			},
		},
	}

	tool := toolDef{
		name:       "grafana",
		sourceType: SourceMetrics,
		images:     []string{"grafana/grafana"},
		port:       3000,
		probePath:  "/api/health",
		endpoint:   "http://%s:3000",
	}

	source := detectToolDocker(tool, containers)
	if source == nil {
		t.Fatal("detectTool returned nil for matching Docker container")
	}
	// "latest" tag should not be reported as version
	if source.Version != "" {
		t.Errorf("source.Version = %q, want empty for :latest tag", source.Version)
	}
}

func TestBuildEndpoint(t *testing.T) {
	tool := toolDef{
		name:     "prometheus",
		port:     9090,
		endpoint: "http://%s:9090",
	}

	// Container with published port matching default
	container := docker.Container{
		Ports: []docker.Port{
			{Host: 9090, Container: 9090, Protocol: "tcp"},
		},
	}

	ep := buildEndpoint(tool, container)
	// Should contain the port
	if ep == "" {
		t.Error("buildEndpoint returned empty string")
	}

	// Container with different host port
	container2 := docker.Container{
		Ports: []docker.Port{
			{Host: 19090, Container: 9090, Protocol: "tcp"},
		},
	}

	ep2 := buildEndpoint(tool, container2)
	if ep2 == "" {
		t.Error("buildEndpoint returned empty for remapped port")
	}
	// The remapped port should use the host port
	if ep2 != "" && !containsPort(ep2, 19090) {
		t.Errorf("buildEndpoint should use host port 19090, got %s", ep2)
	}
}

func containsPort(endpoint string, port uint16) bool {
	return len(endpoint) > 0 && // just a basic check
		(endpoint[len(endpoint)-5:] == ":19090" || endpoint[len(endpoint)-6:] == ":19090")
}

func TestDetectFullPipeline(t *testing.T) {
	// Test the full Detect function with some containers
	containers := []docker.Container{
		{
			Name:   "prometheus",
			Image:  "prom/prometheus:2.51.0",
			Status: "running",
			Ports:  []docker.Port{{Host: 9090, Container: 9090}},
		},
		{
			Name:   "grafana",
			Image:  "grafana/grafana:11.0.0",
			Status: "running",
			Ports:  []docker.Port{{Host: 3000, Container: 3000}},
		},
		{
			Name:   "nginx",
			Image:  "nginx:latest",
			Status: "running",
		},
	}

	result := Detect(containers)
	if result == nil {
		t.Fatal("Detect returned nil")
	}

	// Should have detected at least prometheus and grafana via Docker
	foundProm := false
	foundGrafana := false
	for _, d := range result.Detected {
		if d.Name == "prometheus" {
			foundProm = true
		}
		if d.Name == "grafana" {
			foundGrafana = true
		}
	}
	if !foundProm {
		t.Error("Detect did not find prometheus from container list")
	}
	if !foundGrafana {
		t.Error("Detect did not find grafana from container list")
	}

	// Missing should not include metrics (prometheus covers it)
	for _, m := range result.Missing {
		if m.Type == SourceMetrics {
			t.Error("Metrics should not be in missing list (prometheus detected)")
		}
	}
}

func TestDetectHost(t *testing.T) {
	host := detectHost()
	// On a non-Docker system, should return localhost
	// In Docker, should return host.docker.internal
	if host != "localhost" && host != "host.docker.internal" {
		t.Errorf("detectHost() = %q, want localhost or host.docker.internal", host)
	}
}

func TestKnownToolsComplete(t *testing.T) {
	// Verify all known tools have the required fields
	for _, tool := range knownTools {
		if tool.name == "" {
			t.Error("tool has empty name")
		}
		if tool.sourceType == "" {
			t.Errorf("tool %q has empty sourceType", tool.name)
		}
		// Every tool must have at least one detection method
		hasMethod := len(tool.images) > 0 || tool.port > 0 || len(tool.binaries) > 0 || len(tool.configPaths) > 0
		if !hasMethod {
			t.Errorf("tool %q has no detection method (images, port, binaries, or configPaths)", tool.name)
		}
		if tool.endpoint == "" {
			t.Errorf("tool %q has empty endpoint", tool.name)
		}
	}
}

func TestSourceTypes(t *testing.T) {
	// Verify all defined source types are represented in the tool list
	typeCount := make(map[SourceType]int)
	for _, tool := range knownTools {
		typeCount[tool.sourceType]++
	}

	expectedTypes := []SourceType{SourceCVE, SourceMetrics, SourceUptime, SourceLogs, SourceVuln, SourceNetSec}
	for _, st := range expectedTypes {
		if typeCount[st] == 0 {
			t.Errorf("no tools defined for source type %q", st)
		}
	}
}
