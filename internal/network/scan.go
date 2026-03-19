package network

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Device represents a discovered network device.
type Device struct {
	IP       string     `json:"ip"`
	Hostname string     `json:"hostname,omitempty"`
	MAC      string     `json:"mac,omitempty"`
	Vendor   string     `json:"vendor,omitempty"`
	Type     string     `json:"type,omitempty"` // router, server, nas, printer, iot, workstation, unknown
	Ports    []Port     `json:"ports,omitempty"`
	SNMP     *SNMPInfo  `json:"snmp,omitempty"`
}

// Port represents an open port on a device.
type Port struct {
	Number   uint16 `json:"number"`
	Protocol string `json:"protocol"` // tcp, udp
	Service  string `json:"service,omitempty"`
}

// SNMPInfo holds data retrieved via SNMP from a device.
type SNMPInfo struct {
	SysName     string `json:"sys_name,omitempty"`
	SysDescr    string `json:"sys_descr,omitempty"`
	SysLocation string `json:"sys_location,omitempty"`
	SysContact  string `json:"sys_contact,omitempty"`
	Uptime      string `json:"uptime,omitempty"`
}

// ScanResult holds the results of a network scan.
type ScanResult struct {
	Subnet  string   `json:"subnet"`
	Devices []Device `json:"devices"`
}

// ScanOptions controls what the network scanner does.
type ScanOptions struct {
	ScanPorts bool // probe common TCP ports
	ScanSNMP  bool // attempt SNMP v2c queries (community "public")
}

// commonPorts are the ports we probe by default — enough to identify
// common homelab services without being noisy.
var commonPorts = []uint16{
	22,    // SSH
	53,    // DNS
	80,    // HTTP
	161,   // SNMP
	443,   // HTTPS
	445,   // SMB
	548,   // AFP
	631,   // CUPS/IPP
	3000,  // Grafana, dev servers
	3306,  // MySQL
	5000,  // Docker registry, Synology
	5001,  // Synology HTTPS
	5432,  // PostgreSQL
	5678,  // n8n
	6379,  // Redis
	8080,  // HTTP alt
	8443,  // HTTPS alt
	8888,  // HTTP alt
	9090,  // Prometheus
	9443,  // Portainer
	32400, // Plex
}

// wellKnownServices maps port numbers to service names.
var wellKnownServices = map[uint16]string{
	22:    "ssh",
	53:    "dns",
	80:    "http",
	161:   "snmp",
	443:   "https",
	445:   "smb",
	548:   "afp",
	631:   "ipp",
	3000:  "grafana",
	3306:  "mysql",
	5000:  "docker-registry",
	5001:  "synology-https",
	5432:  "postgresql",
	5678:  "n8n",
	6379:  "redis",
	8080:  "http-alt",
	8443:  "https-alt",
	8888:  "http-alt",
	9090:  "prometheus",
	9443:  "portainer",
	32400: "plex",
}

// ScanSubnet discovers devices on the given subnet.
func ScanSubnet(ctx context.Context, subnet string, opts ScanOptions) (*ScanResult, error) {
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, fmt.Errorf("invalid subnet %q: %w", subnet, err)
	}

	result := &ScanResult{Subnet: subnet}

	// Step 1: Discover live hosts
	hosts := enumerateHosts(ipNet)
	fmt.Fprintf(os.Stderr, "  Scanning %d addresses in %s...\n", len(hosts), subnet)

	liveHosts := pingSweep(ctx, hosts)
	fmt.Fprintf(os.Stderr, "  Found %d live hosts\n", len(liveHosts))

	// Step 2: Enrich each host
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 20) // concurrency limit

	for _, ip := range liveHosts {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			dev := enrichDevice(ctx, ip, opts)
			mu.Lock()
			result.Devices = append(result.Devices, dev)
			mu.Unlock()
		}(ip)
	}
	wg.Wait()

	return result, nil
}

// DetectSubnet finds the primary local subnet from network interfaces.
func DetectSubnet() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP.To4() == nil || ipNet.IP.IsLoopback() {
				continue
			}
			masked := ipNet.IP.Mask(ipNet.Mask)
			ones, _ := ipNet.Mask.Size()
			return fmt.Sprintf("%s/%d", masked, ones)
		}
	}
	return ""
}

// enumerateHosts returns all usable host IPs in the subnet.
func enumerateHosts(ipNet *net.IPNet) []string {
	var hosts []string
	ip := make(net.IP, len(ipNet.IP))
	copy(ip, ipNet.IP)

	for inc(ip); ipNet.Contains(ip); inc(ip) {
		if isBroadcast(ip, ipNet) {
			continue
		}
		hosts = append(hosts, ip.String())
	}
	return hosts
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func isBroadcast(ip net.IP, ipNet *net.IPNet) bool {
	for i := range ip {
		if ip[i] != (ipNet.IP[i] | ^ipNet.Mask[i]) {
			return false
		}
	}
	return true
}

// pingSweep does a concurrent host discovery using ICMP ping with TCP
// connect fallback.
func pingSweep(ctx context.Context, hosts []string) []string {
	var live []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 50)

	for _, host := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if isAlive(ctx, h) {
				mu.Lock()
				live = append(live, h)
				mu.Unlock()
			}
		}(host)
	}
	wg.Wait()
	return live
}

// isAlive checks if a host is reachable via ICMP or TCP fallback.
func isAlive(ctx context.Context, host string) bool {
	pingCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	if err := exec.CommandContext(pingCtx, "ping", "-c", "1", "-W", "1", host).Run(); err == nil {
		return true
	}

	// Fallback: TCP connect to common ports
	for _, port := range []uint16{80, 443, 22, 445} {
		addr := fmt.Sprintf("%s:%d", host, port)
		conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

// enrichDevice builds a Device struct with hostname, MAC, vendor, ports, SNMP.
func enrichDevice(ctx context.Context, ip string, opts ScanOptions) Device {
	dev := Device{
		IP:   ip,
		Type: "unknown",
	}

	// Reverse DNS
	names, err := net.LookupAddr(ip)
	if err == nil && len(names) > 0 {
		dev.Hostname = strings.TrimSuffix(names[0], ".")
	}

	// MAC from ARP table
	dev.MAC = lookupMAC(ip)
	if dev.MAC != "" {
		dev.Vendor = lookupVendor(dev.MAC)
	}

	// Port scan
	if opts.ScanPorts {
		dev.Ports = scanDevicePorts(ctx, ip)
	}

	// SNMP query
	if opts.ScanSNMP {
		dev.SNMP = querySNMP(ctx, ip)
	}

	// Infer type from all available data
	dev.Type = inferDeviceType(dev)

	return dev
}

// lookupMAC reads the ARP table for a MAC address.
func lookupMAC(ip string) string {
	// Try arp -n (Linux) first, then arp (macOS/BSD)
	for _, args := range [][]string{{"-n", ip}, {ip}} {
		out, err := exec.Command("arp", args...).Output()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(out), "\n") {
			for _, field := range strings.Fields(line) {
				if isMAC(field) {
					return strings.ToUpper(field)
				}
			}
		}
	}
	return ""
}

func isMAC(s string) bool {
	if len(s) != 17 {
		return false
	}
	for i, c := range s {
		if i%3 == 2 {
			if c != ':' && c != '-' {
				return false
			}
		} else {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}
	return true
}

// lookupVendor does an OUI lookup for the first 3 bytes of the MAC.
func lookupVendor(mac string) string {
	if len(mac) < 8 {
		return ""
	}
	oui := strings.ToUpper(mac[:8])
	oui = strings.ReplaceAll(oui, "-", ":")

	if vendor, ok := ouiTable[oui]; ok {
		return vendor
	}
	return ""
}

// scanDevicePorts probes common ports on a single device.
func scanDevicePorts(ctx context.Context, ip string) []Port {
	var ports []Port
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, p := range commonPorts {
		wg.Add(1)
		go func(port uint16) {
			defer wg.Done()
			addr := fmt.Sprintf("%s:%d", ip, port)
			conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
			if err == nil {
				conn.Close()
				mu.Lock()
				ports = append(ports, Port{
					Number:   port,
					Protocol: "tcp",
					Service:  wellKnownServices[port],
				})
				mu.Unlock()
			}
		}(p)
	}
	wg.Wait()

	return ports
}

// inferDeviceType guesses the device type from all available signals.
func inferDeviceType(dev Device) string {
	portSet := make(map[uint16]bool)
	for _, p := range dev.Ports {
		portSet[p.Number] = true
	}

	hostname := strings.ToLower(dev.Hostname)
	sysDescr := ""
	if dev.SNMP != nil {
		sysDescr = strings.ToLower(dev.SNMP.SysDescr)
	}

	// SNMP-informed classification (highest confidence)
	if sysDescr != "" {
		if strings.Contains(sysDescr, "router") || strings.Contains(sysDescr, "cisco") ||
			strings.Contains(sysDescr, "routeros") || strings.Contains(sysDescr, "ubiquiti") ||
			strings.Contains(sysDescr, "edgeos") || strings.Contains(sysDescr, "openwrt") {
			return "router"
		}
		if strings.Contains(sysDescr, "switch") || strings.Contains(sysDescr, "catalyst") {
			return "switch"
		}
		if strings.Contains(sysDescr, "ups") || strings.Contains(sysDescr, "apc") ||
			strings.Contains(sysDescr, "cyberpower") || strings.Contains(sysDescr, "eaton") {
			return "ups"
		}
		if strings.Contains(sysDescr, "synology") || strings.Contains(sysDescr, "qnap") ||
			strings.Contains(sysDescr, "freenas") || strings.Contains(sysDescr, "truenas") {
			return "nas"
		}
		if strings.Contains(sysDescr, "printer") || strings.Contains(sysDescr, "brother") ||
			strings.Contains(sysDescr, "canon") || strings.Contains(sysDescr, "hp ") ||
			strings.Contains(sysDescr, "epson") {
			return "printer"
		}
	}

	// Hostname-based
	if strings.Contains(hostname, "router") || strings.Contains(hostname, "gateway") {
		return "router"
	}

	// NAS indicators
	if portSet[5000] || portSet[5001] || portSet[548] ||
		strings.Contains(hostname, "nas") || strings.Contains(hostname, "synology") ||
		strings.Contains(hostname, "qnap") {
		return "nas"
	}

	// Server indicators (multiple service ports)
	serverPorts := 0
	for _, p := range []uint16{22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9090} {
		if portSet[p] {
			serverPorts++
		}
	}
	if serverPorts >= 3 {
		return "server"
	}

	// Printer
	if portSet[631] && !portSet[22] {
		return "printer"
	}

	// IoT (very few ports, just HTTP)
	if len(dev.Ports) <= 1 && (portSet[80] || portSet[443]) {
		return "iot"
	}

	if len(dev.Ports) > 0 {
		return "workstation"
	}

	return "unknown"
}
