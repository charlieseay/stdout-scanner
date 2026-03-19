package delta

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charlieseay/stdout-scanner/internal/docker"
	"github.com/charlieseay/stdout-scanner/internal/network"
	"github.com/charlieseay/stdout-scanner/internal/output"
)

// DeltaResult captures what changed between two scans.
type DeltaResult struct {
	PreviousScan string           `json:"previous_scan"`
	CurrentScan  string           `json:"current_scan"`
	Containers   ContainerDelta   `json:"containers,omitempty"`
	Networks     NetworkDelta     `json:"networks,omitempty"`
	Devices      DeviceDelta      `json:"devices,omitempty"`
	Alerts       []Alert          `json:"alerts,omitempty"`
}

// ContainerDelta tracks container changes.
type ContainerDelta struct {
	Added   []docker.Container `json:"added,omitempty"`
	Removed []docker.Container `json:"removed,omitempty"`
	Changed []ContainerChange  `json:"changed,omitempty"`
}

// ContainerChange describes what changed on a single container.
type ContainerChange struct {
	Name    string   `json:"name"`
	Changes []Change `json:"changes"`
}

// Change is a single field change.
type Change struct {
	Field string `json:"field"`
	From  string `json:"from"`
	To    string `json:"to"`
}

// NetworkDelta tracks Docker network changes.
type NetworkDelta struct {
	Added   []docker.Network `json:"added,omitempty"`
	Removed []docker.Network `json:"removed,omitempty"`
}

// DeviceDelta tracks network device changes.
type DeviceDelta struct {
	Added   []network.Device `json:"added,omitempty"`
	Removed []network.Device `json:"removed,omitempty"`
	Changed []DeviceChange   `json:"changed,omitempty"`
}

// DeviceChange describes what changed on a network device.
type DeviceChange struct {
	IP      string   `json:"ip"`
	Changes []Change `json:"changes"`
}

// Alert represents a significant infrastructure change worth flagging.
type Alert struct {
	Severity string `json:"severity"` // info, warning, critical
	Message  string `json:"message"`
}

// Compare diffs two scan results and returns what changed.
func Compare(previous, current output.ScanResult) *DeltaResult {
	delta := &DeltaResult{
		PreviousScan: previous.ScannedAt,
		CurrentScan:  current.ScannedAt,
	}

	delta.Containers = diffContainers(previous.Containers, current.Containers)
	delta.Networks = diffNetworks(previous.Networks, current.Networks)
	delta.Devices = diffDevices(previous.NetworkDevices, current.NetworkDevices)
	delta.Alerts = generateAlerts(delta)

	return delta
}

// HasChanges returns true if the delta contains any meaningful changes.
func (d *DeltaResult) HasChanges() bool {
	return len(d.Containers.Added) > 0 ||
		len(d.Containers.Removed) > 0 ||
		len(d.Containers.Changed) > 0 ||
		len(d.Networks.Added) > 0 ||
		len(d.Networks.Removed) > 0 ||
		len(d.Devices.Added) > 0 ||
		len(d.Devices.Removed) > 0 ||
		len(d.Devices.Changed) > 0
}

func diffContainers(prev, curr []docker.Container) ContainerDelta {
	var d ContainerDelta

	prevMap := make(map[string]docker.Container)
	for _, c := range prev {
		prevMap[c.Name] = c
	}
	currMap := make(map[string]docker.Container)
	for _, c := range curr {
		currMap[c.Name] = c
	}

	// Added
	for name, c := range currMap {
		if _, ok := prevMap[name]; !ok {
			d.Added = append(d.Added, c)
		}
	}

	// Removed
	for name, c := range prevMap {
		if _, ok := currMap[name]; !ok {
			d.Removed = append(d.Removed, c)
		}
	}

	// Changed
	for name, curr := range currMap {
		prev, ok := prevMap[name]
		if !ok {
			continue
		}
		var changes []Change

		if prev.Image != curr.Image {
			changes = append(changes, Change{Field: "image", From: prev.Image, To: curr.Image})
		}
		if prev.Status != curr.Status {
			changes = append(changes, Change{Field: "status", From: prev.Status, To: curr.Status})
		}
		if prev.Health != curr.Health {
			changes = append(changes, Change{Field: "health", From: prev.Health, To: curr.Health})
		}
		if prev.RestartPolicy != curr.RestartPolicy {
			changes = append(changes, Change{Field: "restart_policy", From: prev.RestartPolicy, To: curr.RestartPolicy})
		}

		if len(changes) > 0 {
			d.Changed = append(d.Changed, ContainerChange{
				Name:    name,
				Changes: changes,
			})
		}
	}

	return d
}

func diffNetworks(prev, curr []docker.Network) NetworkDelta {
	var d NetworkDelta

	prevMap := make(map[string]docker.Network)
	for _, n := range prev {
		prevMap[n.Name] = n
	}
	currMap := make(map[string]docker.Network)
	for _, n := range curr {
		currMap[n.Name] = n
	}

	for name, n := range currMap {
		if _, ok := prevMap[name]; !ok {
			d.Added = append(d.Added, n)
		}
	}
	for name, n := range prevMap {
		if _, ok := currMap[name]; !ok {
			d.Removed = append(d.Removed, n)
		}
	}

	return d
}

func diffDevices(prevScans, currScans []network.ScanResult) DeviceDelta {
	var d DeviceDelta

	// Flatten all devices from all subnet scans
	prevDevs := make(map[string]network.Device)
	for _, s := range prevScans {
		for _, dev := range s.Devices {
			prevDevs[dev.IP] = dev
		}
	}
	currDevs := make(map[string]network.Device)
	for _, s := range currScans {
		for _, dev := range s.Devices {
			currDevs[dev.IP] = dev
		}
	}

	for ip, dev := range currDevs {
		if _, ok := prevDevs[ip]; !ok {
			d.Added = append(d.Added, dev)
		}
	}
	for ip, dev := range prevDevs {
		if _, ok := currDevs[ip]; !ok {
			d.Removed = append(d.Removed, dev)
		}
	}

	// Changed (type, hostname, open ports)
	for ip, curr := range currDevs {
		prev, ok := prevDevs[ip]
		if !ok {
			continue
		}
		var changes []Change

		if prev.Type != curr.Type {
			changes = append(changes, Change{Field: "type", From: prev.Type, To: curr.Type})
		}
		if prev.Hostname != curr.Hostname {
			changes = append(changes, Change{Field: "hostname", From: prev.Hostname, To: curr.Hostname})
		}

		prevPorts := portsString(prev.Ports)
		currPorts := portsString(curr.Ports)
		if prevPorts != currPorts {
			changes = append(changes, Change{Field: "ports", From: prevPorts, To: currPorts})
		}

		if len(changes) > 0 {
			d.Changed = append(d.Changed, DeviceChange{
				IP:      ip,
				Changes: changes,
			})
		}
	}

	return d
}

func portsString(ports []network.Port) string {
	if len(ports) == 0 {
		return ""
	}
	var parts []string
	for _, p := range ports {
		s := fmt.Sprintf("%d/%s", p.Number, p.Protocol)
		parts = append(parts, s)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func generateAlerts(delta *DeltaResult) []Alert {
	var alerts []Alert

	// Container alerts
	for _, c := range delta.Containers.Added {
		alerts = append(alerts, Alert{
			Severity: "info",
			Message:  "New container: " + c.Name + " (" + c.Image + ")",
		})
	}
	for _, c := range delta.Containers.Removed {
		alerts = append(alerts, Alert{
			Severity: "warning",
			Message:  "Container removed: " + c.Name + " (" + c.Image + ")",
		})
	}
	for _, cc := range delta.Containers.Changed {
		for _, ch := range cc.Changes {
			switch ch.Field {
			case "image":
				alerts = append(alerts, Alert{
					Severity: "info",
					Message:  cc.Name + " image updated: " + ch.From + " → " + ch.To,
				})
			case "status":
				if ch.To == "stopped" || ch.To == "paused" {
					alerts = append(alerts, Alert{
						Severity: "warning",
						Message:  cc.Name + " " + ch.To + " (was " + ch.From + ")",
					})
				}
			case "health":
				if ch.To == "unhealthy" {
					alerts = append(alerts, Alert{
						Severity: "critical",
						Message:  cc.Name + " became unhealthy (was " + ch.From + ")",
					})
				}
			}
		}
	}

	// Network device alerts
	for _, dev := range delta.Devices.Added {
		severity := "info"
		if dev.Type == "unknown" {
			severity = "warning"
		}
		label := dev.IP
		if dev.Hostname != "" {
			label = dev.Hostname + " (" + dev.IP + ")"
		}
		alerts = append(alerts, Alert{
			Severity: severity,
			Message:  "New device on network: " + label + " [" + dev.Type + "]",
		})
	}
	for _, dev := range delta.Devices.Removed {
		label := dev.IP
		if dev.Hostname != "" {
			label = dev.Hostname + " (" + dev.IP + ")"
		}
		alerts = append(alerts, Alert{
			Severity: "info",
			Message:  "Device gone: " + label,
		})
	}

	return alerts
}
