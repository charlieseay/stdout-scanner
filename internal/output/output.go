package output

import (
	"fmt"
	"strings"
	"time"

	"github.com/charlieseay/stdout-scanner/internal/docker"
	"github.com/charlieseay/stdout-scanner/internal/host"
)

type ScanResult struct {
	Version    string             `json:"version"`
	ScannedAt  string             `json:"scanned_at"`
	Host       *host.Info         `json:"host,omitempty"`
	Containers []docker.Container `json:"containers"`
	Networks   []docker.Network   `json:"networks,omitempty"`
}

func Now() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func RenderMarkdown(scan ScanResult) string {
	var b strings.Builder

	b.WriteString("# Infrastructure Stack\n")
	b.WriteString(fmt.Sprintf("Scanned: %s\n\n", scan.ScannedAt))

	// Host info
	if scan.Host != nil {
		b.WriteString("## Host\n")
		if scan.Host.OS != "" {
			b.WriteString(fmt.Sprintf("- OS: %s (%s)\n", scan.Host.OS, scan.Host.Arch))
		}
		if scan.Host.CPUCores > 0 {
			b.WriteString(fmt.Sprintf("- CPU: %d cores\n", scan.Host.CPUCores))
		}
		if scan.Host.MemoryGB > 0 {
			b.WriteString(fmt.Sprintf("- RAM: %.1f GB\n", scan.Host.MemoryGB))
		}
		for _, d := range scan.Host.Disk {
			b.WriteString(fmt.Sprintf("- Disk %s: %.1f/%.1f GB used\n", d.Mount, d.UsedGB, d.TotalGB))
		}
		b.WriteString("\n")
	}

	// Containers
	running := 0
	for _, c := range scan.Containers {
		if c.Status == "running" {
			running++
		}
	}
	b.WriteString(fmt.Sprintf("## Containers (%d running, %d total)\n\n", running, len(scan.Containers)))

	for _, c := range scan.Containers {
		b.WriteString(fmt.Sprintf("### %s (%s)\n", c.Name, c.Image))
		if len(c.Ports) > 0 {
			ports := make([]string, len(c.Ports))
			for i, p := range c.Ports {
				ports[i] = fmt.Sprintf("%d:%d", p.Host, p.Container)
			}
			b.WriteString(fmt.Sprintf("- Ports: %s\n", strings.Join(ports, ", ")))
		}
		if len(c.Networks) > 0 {
			b.WriteString(fmt.Sprintf("- Networks: %s\n", strings.Join(c.Networks, ", ")))
		}
		if c.Health != "" {
			b.WriteString(fmt.Sprintf("- Health: %s\n", c.Health))
		}
		b.WriteString(fmt.Sprintf("- Status: %s\n", c.Status))
		if c.ComposeProject != "" {
			b.WriteString(fmt.Sprintf("- Compose: %s/%s\n", c.ComposeProject, c.ComposeService))
		}
		if c.RestartPolicy != "" {
			b.WriteString(fmt.Sprintf("- Restart: %s\n", c.RestartPolicy))
		}
		b.WriteString("\n")
	}

	// Networks
	if len(scan.Networks) > 0 {
		b.WriteString("## Networks\n\n")
		for _, n := range scan.Networks {
			b.WriteString(fmt.Sprintf("### %s\n", n.Name))
			b.WriteString(fmt.Sprintf("- Driver: %s\n", n.Driver))
			if n.Subnet != "" {
				b.WriteString(fmt.Sprintf("- Subnet: %s\n", n.Subnet))
			}
			if len(n.Containers) > 0 {
				b.WriteString(fmt.Sprintf("- Containers: %s\n", strings.Join(n.Containers, ", ")))
			}
			b.WriteString("\n")
		}
	}

	return b.String()
}
