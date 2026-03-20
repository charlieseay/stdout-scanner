package network

import "strings"

// HostClass represents the classification of a discovered host.
type HostClass int

const (
	HostClassUnknown  HostClass = iota
	HostClassServer             // Server, NAS, router, switch, infrastructure
	HostClassEndpoint           // Workstation, phone, tablet, IoT
)

// ClassifyHost determines whether a device is a server or endpoint
// based on all available signals. Used for --scan-targets filtering.
//
// Classification happens after initial discovery (ping sweep + ARP)
// but before deep enrichment (full port scan, SNMP, DNS).
// We use lightweight signals: open ports from the quick probe,
// OUI vendor, hostname, and device type if already inferred.
func ClassifyHost(dev Device) HostClass {
	// If type was already inferred with high confidence, use it
	switch dev.Type {
	case "server", "nas", "router", "switch", "ups", "printer":
		return HostClassServer
	case "iot":
		return HostClassEndpoint
	// "workstation" is low-confidence from inferDeviceType — re-evaluate below
	}

	// Check OUI for mobile/endpoint vendors
	vendor := strings.ToLower(dev.Vendor)
	if isEndpointVendor(vendor) {
		return HostClassEndpoint
	}

	// Check hostname patterns
	hostname := strings.ToLower(dev.Hostname)
	if isServerHostname(hostname) {
		return HostClassServer
	}
	if isEndpointHostname(hostname) {
		return HostClassEndpoint
	}

	// Check port profile
	serverPorts := 0
	for _, p := range dev.Ports {
		if isServerPort(p.Number) {
			serverPorts++
		}
	}
	if serverPorts >= 2 {
		return HostClassServer
	}

	// Default: server when ambiguous — safer for homelab context
	// (better to scan too much than miss infrastructure)
	if len(dev.Ports) > 0 {
		return HostClassServer
	}

	return HostClassUnknown
}

// MatchesTargetFilter checks if a device should be included based on
// the --scan-targets filter value.
func MatchesTargetFilter(dev Device, filter string) bool {
	switch filter {
	case "servers":
		class := ClassifyHost(dev)
		return class == HostClassServer || class == HostClassUnknown
	case "endpoints":
		return ClassifyHost(dev) == HostClassEndpoint
	default: // "all"
		return true
	}
}

func isServerPort(port uint16) bool {
	switch port {
	case 22, 53, 80, 443, 445, 548, 631, 3000, 3306, 5000, 5001,
		5432, 5678, 6379, 8080, 8443, 8888, 9090, 9443, 32400:
		return true
	}
	return false
}

// endpointVendors are OUI vendor substrings that strongly indicate
// end-user devices (phones, laptops, tablets).
var endpointVendors = []string{
	"apple",     // iPhones, iPads, MacBooks (ambiguous — also servers)
	"samsung",
	"google",    // Pixel, Chromecast
	"amazon",    // Echo, Fire
	"sonos",
	"roku",
	"ring",
	"nest",
	"ecobee",
	"bose",
	"microsoft", // Surface
	"intel",     // laptops/desktops with Intel NICs
}

func isEndpointVendor(vendor string) bool {
	// Apple is ambiguous — Mac Minis and iMacs are servers in homelabs.
	// Only classify as endpoint if no server ports are open.
	// This is handled by the port check above, so we skip Apple here.
	if vendor == "" {
		return false
	}
	for _, ev := range endpointVendors {
		if ev == "apple" || ev == "intel" || ev == "microsoft" {
			continue // too ambiguous
		}
		if strings.Contains(vendor, ev) {
			return true
		}
	}
	return false
}

func isServerHostname(hostname string) bool {
	serverPatterns := []string{
		"server", "srv", "nas", "router", "gateway", "switch",
		"proxy", "docker", "k8s", "kube", "node", "host",
		"db", "redis", "postgres", "mysql", "mongo",
		"plex", "pihole", "unifi", "opnsense", "pfsense",
		"truenas", "synology", "qnap", "proxmox",
	}
	for _, p := range serverPatterns {
		if strings.Contains(hostname, p) {
			return true
		}
	}
	return false
}

func isEndpointHostname(hostname string) bool {
	endpointPatterns := []string{
		"iphone", "ipad", "macbook", "pixel", "galaxy",
		"laptop", "desktop", "workstation", "pc-",
		"chromecast", "firestick", "appletv", "roku",
	}
	for _, p := range endpointPatterns {
		if strings.Contains(hostname, p) {
			return true
		}
	}
	return false
}
