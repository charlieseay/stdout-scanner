package delta

import (
	"fmt"
	"strings"
)

// RenderMarkdown produces a human-readable delta report.
func RenderMarkdown(d *DeltaResult) string {
	var b strings.Builder

	b.WriteString("# Infrastructure Delta Report\n")
	b.WriteString(fmt.Sprintf("Previous: %s\n", d.PreviousScan))
	b.WriteString(fmt.Sprintf("Current:  %s\n\n", d.CurrentScan))

	if !d.HasChanges() {
		b.WriteString("No changes detected.\n")
		return b.String()
	}

	// Alerts first — the TL;DR
	if len(d.Alerts) > 0 {
		b.WriteString("## Alerts\n\n")
		for _, a := range d.Alerts {
			icon := "i"
			switch a.Severity {
			case "warning":
				icon = "!"
			case "critical":
				icon = "!!"
			}
			b.WriteString(fmt.Sprintf("- [%s] %s\n", icon, a.Message))
		}
		b.WriteString("\n")
	}

	// Container changes
	if len(d.Containers.Added) > 0 || len(d.Containers.Removed) > 0 || len(d.Containers.Changed) > 0 {
		b.WriteString("## Containers\n\n")

		for _, c := range d.Containers.Added {
			b.WriteString(fmt.Sprintf("+ **%s** (%s)\n", c.Name, c.Image))
		}
		for _, c := range d.Containers.Removed {
			b.WriteString(fmt.Sprintf("- **%s** (%s)\n", c.Name, c.Image))
		}
		for _, cc := range d.Containers.Changed {
			b.WriteString(fmt.Sprintf("~ **%s**\n", cc.Name))
			for _, ch := range cc.Changes {
				b.WriteString(fmt.Sprintf("  %s: %s → %s\n", ch.Field, ch.From, ch.To))
			}
		}
		b.WriteString("\n")
	}

	// Network changes
	if len(d.Networks.Added) > 0 || len(d.Networks.Removed) > 0 {
		b.WriteString("## Docker Networks\n\n")
		for _, n := range d.Networks.Added {
			b.WriteString(fmt.Sprintf("+ **%s** (%s)\n", n.Name, n.Driver))
		}
		for _, n := range d.Networks.Removed {
			b.WriteString(fmt.Sprintf("- **%s** (%s)\n", n.Name, n.Driver))
		}
		b.WriteString("\n")
	}

	// Device changes
	if len(d.Devices.Added) > 0 || len(d.Devices.Removed) > 0 || len(d.Devices.Changed) > 0 {
		b.WriteString("## Network Devices\n\n")
		for _, dev := range d.Devices.Added {
			label := dev.IP
			if dev.Hostname != "" {
				label = dev.Hostname + " (" + dev.IP + ")"
			}
			b.WriteString(fmt.Sprintf("+ **%s** [%s]\n", label, dev.Type))
		}
		for _, dev := range d.Devices.Removed {
			label := dev.IP
			if dev.Hostname != "" {
				label = dev.Hostname + " (" + dev.IP + ")"
			}
			b.WriteString(fmt.Sprintf("- **%s** [%s]\n", label, dev.Type))
		}
		for _, dc := range d.Devices.Changed {
			b.WriteString(fmt.Sprintf("~ **%s**\n", dc.IP))
			for _, ch := range dc.Changes {
				b.WriteString(fmt.Sprintf("  %s: %s → %s\n", ch.Field, ch.From, ch.To))
			}
		}
		b.WriteString("\n")
	}

	return b.String()
}

// RenderOneLiner produces a single-line summary for logging/notifications.
func RenderOneLiner(d *DeltaResult) string {
	if !d.HasChanges() {
		return "No changes"
	}

	var parts []string

	if n := len(d.Containers.Added); n > 0 {
		parts = append(parts, fmt.Sprintf("+%d containers", n))
	}
	if n := len(d.Containers.Removed); n > 0 {
		parts = append(parts, fmt.Sprintf("-%d containers", n))
	}
	if n := len(d.Containers.Changed); n > 0 {
		parts = append(parts, fmt.Sprintf("~%d containers", n))
	}
	if n := len(d.Devices.Added); n > 0 {
		parts = append(parts, fmt.Sprintf("+%d devices", n))
	}
	if n := len(d.Devices.Removed); n > 0 {
		parts = append(parts, fmt.Sprintf("-%d devices", n))
	}

	critical := 0
	for _, a := range d.Alerts {
		if a.Severity == "critical" {
			critical++
		}
	}
	if critical > 0 {
		parts = append(parts, fmt.Sprintf("%d critical", critical))
	}

	return strings.Join(parts, ", ")
}
