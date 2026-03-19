package output

import (
	"fmt"
	"strings"
	"time"

	"github.com/charlieseay/stdout-scanner/internal/docker"
	"github.com/charlieseay/stdout-scanner/internal/host"
	"github.com/charlieseay/stdout-scanner/internal/metrics"
	"github.com/charlieseay/stdout-scanner/internal/network"
)

type ScanResult struct {
	Version          string                   `json:"version"`
	ScannedAt        string                   `json:"scanned_at"`
	Modules          []string                 `json:"modules"`
	Host             *host.Info               `json:"host,omitempty"`
	HostMetrics      *metrics.HostMetrics     `json:"host_metrics,omitempty"`
	Containers       []docker.Container       `json:"containers,omitempty"`
	ContainerMetrics []metrics.ContainerMetrics `json:"container_metrics,omitempty"`
	Networks         []docker.Network         `json:"networks,omitempty"`
	NetworkDevices   []network.ScanResult     `json:"network_devices,omitempty"`
}

func Now() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func RenderMarkdown(scan ScanResult) string {
	var b strings.Builder

	b.WriteString("# Infrastructure Stack\n")
	b.WriteString(fmt.Sprintf("Scanned: %s\n", scan.ScannedAt))
	if len(scan.Modules) > 0 {
		b.WriteString(fmt.Sprintf("Modules: %s\n", strings.Join(scan.Modules, ", ")))
	}
	b.WriteString("\n")

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

	// Host metrics
	if scan.HostMetrics != nil {
		b.WriteString("## Host Metrics\n")
		m := scan.HostMetrics
		if m.CPUPercent > 0 {
			b.WriteString(fmt.Sprintf("- CPU: %.1f%%\n", m.CPUPercent))
		}
		b.WriteString(fmt.Sprintf("- Memory: %.1f/%.1f GB (%.1f%%)\n", m.MemoryUsedGB, m.MemoryTotalGB, m.MemoryPercent))
		b.WriteString(fmt.Sprintf("- Load: %.2f / %.2f / %.2f\n", m.LoadAvg[0], m.LoadAvg[1], m.LoadAvg[2]))
		if m.Uptime != "" {
			b.WriteString(fmt.Sprintf("- Uptime: %s\n", m.Uptime))
		}
		b.WriteString("\n")
	}

	// Containers
	if len(scan.Containers) > 0 {
		running := 0
		for _, c := range scan.Containers {
			if c.Status == "running" {
				running++
			}
		}
		b.WriteString(fmt.Sprintf("## Containers (%d running, %d total)\n\n", running, len(scan.Containers)))

		// Build a metrics lookup by container name for inline display
		metricsMap := make(map[string]*metrics.ContainerMetrics)
		for i := range scan.ContainerMetrics {
			metricsMap[scan.ContainerMetrics[i].Name] = &scan.ContainerMetrics[i]
		}

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

			// Inline metrics if available
			if m, ok := metricsMap[c.Name]; ok {
				b.WriteString(fmt.Sprintf("- CPU: %.1f%% | Mem: %s/%s (%.1f%%) | PIDs: %d\n",
					m.CPUPercent,
					formatBytes(m.MemoryUsed),
					formatBytes(m.MemoryLimit),
					m.MemoryPercent,
					m.PIDs,
				))
				if m.NetRxBytes > 0 || m.NetTxBytes > 0 {
					b.WriteString(fmt.Sprintf("- Net: %s rx / %s tx\n",
						formatBytes(m.NetRxBytes),
						formatBytes(m.NetTxBytes),
					))
				}
			}

			b.WriteString("\n")
		}
	}

	// Network Devices
	for _, netScan := range scan.NetworkDevices {
		b.WriteString(fmt.Sprintf("## Network Devices — %s (%d found)\n\n", netScan.Subnet, len(netScan.Devices)))

		for _, dev := range netScan.Devices {
			label := dev.IP
			if dev.Hostname != "" {
				label = fmt.Sprintf("%s (%s)", dev.Hostname, dev.IP)
			}
			b.WriteString(fmt.Sprintf("### %s\n", label))
			b.WriteString(fmt.Sprintf("- Type: %s\n", dev.Type))
			if dev.MAC != "" {
				vendor := ""
				if dev.Vendor != "" {
					vendor = " (" + dev.Vendor + ")"
				}
				b.WriteString(fmt.Sprintf("- MAC: %s%s\n", dev.MAC, vendor))
			}
			if len(dev.Ports) > 0 {
				var portStrs []string
				for _, p := range dev.Ports {
					if p.Service != "" {
						portStrs = append(portStrs, fmt.Sprintf("%d/%s (%s)", p.Number, p.Protocol, p.Service))
					} else {
						portStrs = append(portStrs, fmt.Sprintf("%d/%s", p.Number, p.Protocol))
					}
				}
				b.WriteString(fmt.Sprintf("- Ports: %s\n", strings.Join(portStrs, ", ")))
			}
			if dev.SNMP != nil {
				if dev.SNMP.SysName != "" {
					b.WriteString(fmt.Sprintf("- SNMP Name: %s\n", dev.SNMP.SysName))
				}
				if dev.SNMP.SysDescr != "" {
					b.WriteString(fmt.Sprintf("- SNMP Description: %s\n", dev.SNMP.SysDescr))
				}
				if dev.SNMP.SysLocation != "" {
					b.WriteString(fmt.Sprintf("- SNMP Location: %s\n", dev.SNMP.SysLocation))
				}
				if dev.SNMP.Uptime != "" {
					b.WriteString(fmt.Sprintf("- SNMP Uptime: %s\n", dev.SNMP.Uptime))
				}
			}
			b.WriteString("\n")
		}
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

func formatBytes(b uint64) string {
	const (
		kb = 1024
		mb = kb * 1024
		gb = mb * 1024
	)
	switch {
	case b >= gb:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(gb))
	case b >= mb:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(mb))
	case b >= kb:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(kb))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
