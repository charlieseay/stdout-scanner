package network

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// DNSResult holds DNS and service discovery data for a host.
type DNSResult struct {
	IP          string       `json:"ip"`
	Hostname    string       `json:"hostname,omitempty"`
	ForwardMatch bool       `json:"forward_match"` // hostname resolves back to this IP
	MDNSServices []MDNSService `json:"mdns_services,omitempty"`
	ReverseProxy *ProxyInfo  `json:"reverse_proxy,omitempty"`
	TLSCerts     []CertInfo `json:"tls_certs,omitempty"`
}

// MDNSService represents a service advertised via mDNS/Bonjour.
type MDNSService struct {
	Name     string `json:"name"`
	Type     string `json:"type"`     // e.g. _http._tcp
	Port     uint16 `json:"port"`
	Hostname string `json:"hostname,omitempty"`
}

// ProxyInfo holds reverse proxy detection results.
type ProxyInfo struct {
	Software string   `json:"software"`         // nginx, traefik, caddy, etc.
	Domains  []string `json:"domains,omitempty"` // domains served
}

// CertInfo holds TLS certificate details.
type CertInfo struct {
	Port      uint16   `json:"port"`
	Subject   string   `json:"subject"`
	Issuer    string   `json:"issuer"`
	SANs      []string `json:"sans,omitempty"` // Subject Alternative Names
	NotBefore string   `json:"not_before"`
	NotAfter  string   `json:"not_after"`
	DaysLeft  int      `json:"days_left"`
	SelfSigned bool   `json:"self_signed"`
}

// DiscoverDNS runs DNS and service discovery against known devices.
// Takes the already-discovered devices and enriches them with DNS data.
func DiscoverDNS(ctx context.Context, devices []Device) []DNSResult {
	var results []DNSResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for _, dev := range devices {
		wg.Add(1)
		go func(d Device) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			result := discoverDNSForDevice(ctx, d)
			if result != nil {
				mu.Lock()
				results = append(results, *result)
				mu.Unlock()
			}
		}(dev)
	}
	wg.Wait()

	// Also discover mDNS services on the network
	mdnsServices := discoverMDNS(ctx)
	if len(mdnsServices) > 0 {
		fmt.Fprintf(os.Stderr, "    mDNS: found %d advertised services\n", len(mdnsServices))
		// Merge mDNS results into existing device results or create new ones
		results = mergeMDNS(results, mdnsServices)
	}

	return results
}

func discoverDNSForDevice(ctx context.Context, dev Device) *DNSResult {
	result := &DNSResult{
		IP:       dev.IP,
		Hostname: dev.Hostname,
	}

	hasData := false

	// Forward DNS verification: does the hostname resolve back to this IP?
	if dev.Hostname != "" {
		ips, err := net.LookupHost(dev.Hostname)
		if err == nil {
			for _, ip := range ips {
				if ip == dev.IP {
					result.ForwardMatch = true
					break
				}
			}
		}
		hasData = true
	}

	// Check for reverse proxy on HTTP/HTTPS ports
	for _, port := range dev.Ports {
		if port.Number == 80 || port.Number == 443 || port.Number == 8080 || port.Number == 8443 {
			proxy := detectReverseProxy(ctx, dev.IP, port.Number)
			if proxy != nil {
				result.ReverseProxy = proxy
				hasData = true
				break // One proxy detection is enough
			}
		}
	}

	// TLS certificate inspection on HTTPS ports
	for _, port := range dev.Ports {
		if port.Number == 443 || port.Number == 8443 || port.Number == 9443 {
			cert := inspectTLSCert(dev.IP, port.Number)
			if cert != nil {
				result.TLSCerts = append(result.TLSCerts, *cert)
				hasData = true
			}
		}
	}

	if !hasData {
		return nil
	}
	return result
}

// detectReverseProxy checks HTTP(S) response headers for proxy software.
func detectReverseProxy(ctx context.Context, ip string, port uint16) *ProxyInfo {
	scheme := "http"
	if port == 443 || port == 8443 || port == 9443 {
		scheme = "https"
	}

	url := fmt.Sprintf("%s://%s:%d/", scheme, ip, port)

	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}

	req, err := http.NewRequestWithContext(ctx, "HEAD", url, nil)
	if err != nil {
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	info := &ProxyInfo{}

	// Check Server header
	server := resp.Header.Get("Server")
	if server != "" {
		info.Software = identifyProxy(server)
	}

	// Check X-Powered-By
	if powered := resp.Header.Get("X-Powered-By"); powered != "" && info.Software == "" {
		info.Software = powered
	}

	// Check Via header (used by some proxies)
	if via := resp.Header.Get("Via"); via != "" && info.Software == "" {
		info.Software = "proxy (via: " + via + ")"
	}

	// Check for Traefik-specific headers
	if resp.Header.Get("X-Traefik-Backend") != "" {
		info.Software = "Traefik"
	}

	// Check for Cloudflare
	if resp.Header.Get("CF-Ray") != "" {
		info.Software = "Cloudflare"
	}

	// Check for Nginx Proxy Manager redirect pattern
	if location := resp.Header.Get("Location"); location != "" {
		if strings.Contains(location, "congratulations") || strings.Contains(location, "default") {
			if info.Software == "" {
				info.Software = "Nginx Proxy Manager"
			}
		}
	}

	if info.Software == "" {
		return nil
	}

	return info
}

// identifyProxy maps Server header values to known proxy software.
func identifyProxy(server string) string {
	s := strings.ToLower(server)

	switch {
	case strings.Contains(s, "nginx"):
		if strings.Contains(s, "proxy manager") {
			return "Nginx Proxy Manager"
		}
		return "nginx"
	case strings.Contains(s, "traefik"):
		return "Traefik"
	case strings.Contains(s, "caddy"):
		return "Caddy"
	case strings.Contains(s, "apache"):
		return "Apache"
	case strings.Contains(s, "haproxy"):
		return "HAProxy"
	case strings.Contains(s, "envoy"):
		return "Envoy"
	case strings.Contains(s, "lighttpd"):
		return "Lighttpd"
	case strings.Contains(s, "openresty"):
		return "OpenResty"
	default:
		return server
	}
}

// inspectTLSCert connects to a TLS port and reads certificate info.
func inspectTLSCert(ip string, port uint16) *CertInfo {
	addr := fmt.Sprintf("%s:%d", ip, port)

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 3 * time.Second},
		"tcp",
		addr,
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		return nil
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil
	}

	leaf := certs[0]
	daysLeft := int(time.Until(leaf.NotAfter).Hours() / 24)

	info := &CertInfo{
		Port:       port,
		Subject:    leaf.Subject.CommonName,
		Issuer:     leaf.Issuer.CommonName,
		NotBefore:  leaf.NotBefore.Format("2006-01-02"),
		NotAfter:   leaf.NotAfter.Format("2006-01-02"),
		DaysLeft:   daysLeft,
		SelfSigned: leaf.Issuer.CommonName == leaf.Subject.CommonName,
	}

	// SANs
	for _, name := range leaf.DNSNames {
		info.SANs = append(info.SANs, name)
	}
	for _, ip := range leaf.IPAddresses {
		info.SANs = append(info.SANs, ip.String())
	}

	return info
}

// discoverMDNS sends mDNS queries for common service types and
// collects responses. Uses a short timeout since mDNS is local.
func discoverMDNS(ctx context.Context) []MDNSService {
	serviceTypes := []string{
		"_http._tcp.local.",
		"_https._tcp.local.",
		"_ssh._tcp.local.",
		"_smb._tcp.local.",
		"_printer._tcp.local.",
		"_ipp._tcp.local.",
		"_airplay._tcp.local.",
		"_raop._tcp.local.",
		"_googlecast._tcp.local.",
		"_hap._tcp.local.", // HomeKit
		"_companion-link._tcp.local.",
	}

	var services []MDNSService
	var mu sync.Mutex

	// mDNS multicast address
	mdnsAddr := &net.UDPAddr{
		IP:   net.ParseIP("224.0.0.251"),
		Port: 5353,
	}

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 0})
	if err != nil {
		return nil
	}
	defer conn.Close()

	// Send queries for each service type
	for _, svcType := range serviceTypes {
		query := buildMDNSQuery(svcType)
		conn.WriteToUDP(query, mdnsAddr)
	}

	// Collect responses for 2 seconds
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)

	for {
		n, _, err := conn.ReadFromUDP(buf)
		if err != nil {
			break
		}

		found := parseMDNSResponse(buf[:n])
		if len(found) > 0 {
			mu.Lock()
			services = append(services, found...)
			mu.Unlock()
		}
	}

	return deduplicateServices(services)
}

// buildMDNSQuery constructs a minimal DNS query for a service type.
func buildMDNSQuery(name string) []byte {
	// DNS header: ID=0, QR=0, OPCODE=0, 1 question
	header := []byte{
		0x00, 0x00, // ID
		0x00, 0x00, // Flags (standard query)
		0x00, 0x01, // QDCOUNT = 1
		0x00, 0x00, // ANCOUNT = 0
		0x00, 0x00, // NSCOUNT = 0
		0x00, 0x00, // ARCOUNT = 0
	}

	// Encode name
	qname := encodeDNSName(name)

	// QTYPE = PTR (12), QCLASS = IN (1) with unicast bit
	question := append(qname, 0x00, 0x0c, 0x00, 0x01)

	return append(header, question...)
}

// encodeDNSName encodes a domain name in DNS wire format.
func encodeDNSName(name string) []byte {
	name = strings.TrimSuffix(name, ".")
	parts := strings.Split(name, ".")
	var result []byte
	for _, part := range parts {
		result = append(result, byte(len(part)))
		result = append(result, []byte(part)...)
	}
	result = append(result, 0x00) // terminating zero
	return result
}

// parseMDNSResponse extracts service announcements from an mDNS response.
func parseMDNSResponse(data []byte) []MDNSService {
	if len(data) < 12 {
		return nil
	}

	var services []MDNSService

	// Parse answer count from header
	ancount := int(data[6])<<8 | int(data[7])
	nscount := int(data[8])<<8 | int(data[9])
	arcount := int(data[10])<<8 | int(data[11])
	totalRR := ancount + nscount + arcount

	// Skip question section
	offset := 12
	qdcount := int(data[4])<<8 | int(data[5])
	for i := 0; i < qdcount && offset < len(data); i++ {
		offset = skipDNSName(data, offset)
		offset += 4 // QTYPE + QCLASS
	}

	// Parse resource records
	for i := 0; i < totalRR && offset < len(data)-10; i++ {
		name := decodeDNSName(data, offset)
		offset = skipDNSName(data, offset)
		if offset+10 > len(data) {
			break
		}

		rrType := int(data[offset])<<8 | int(data[offset+1])
		offset += 2 // type
		offset += 2 // class
		offset += 4 // TTL
		rdlength := int(data[offset])<<8 | int(data[offset+1])
		offset += 2

		if offset+rdlength > len(data) {
			break
		}

		// PTR record — service instance name
		if rrType == 12 { // PTR
			instanceName := decodeDNSName(data, offset)
			if instanceName != "" && name != "" {
				svc := MDNSService{
					Name: cleanServiceName(instanceName, name),
					Type: cleanServiceType(name),
				}
				services = append(services, svc)
			}
		}

		// SRV record — has port and target hostname
		if rrType == 33 && rdlength >= 6 { // SRV
			port := uint16(data[offset+4])<<8 | uint16(data[offset+5])
			target := decodeDNSName(data, offset+6)
			for j := range services {
				if services[j].Port == 0 {
					services[j].Port = port
					services[j].Hostname = target
				}
			}
		}

		offset += rdlength
	}

	return services
}

// skipDNSName advances past a DNS name in wire format.
func skipDNSName(data []byte, offset int) int {
	for offset < len(data) {
		length := int(data[offset])
		if length == 0 {
			return offset + 1
		}
		if length >= 0xc0 { // pointer
			return offset + 2
		}
		offset += 1 + length
	}
	return offset
}

// decodeDNSName reads a DNS name from wire format with pointer support.
func decodeDNSName(data []byte, offset int) string {
	var parts []string
	visited := make(map[int]bool) // prevent infinite loops

	for offset < len(data) {
		if visited[offset] {
			break
		}
		visited[offset] = true

		length := int(data[offset])
		if length == 0 {
			break
		}
		if length >= 0xc0 { // pointer
			if offset+1 >= len(data) {
				break
			}
			ptr := (int(data[offset]&0x3f) << 8) | int(data[offset+1])
			return strings.Join(parts, ".") + "." + decodeDNSName(data, ptr)
		}
		offset++
		if offset+length > len(data) {
			break
		}
		parts = append(parts, string(data[offset:offset+length]))
		offset += length
	}
	return strings.Join(parts, ".")
}

func cleanServiceName(instance, serviceType string) string {
	// Remove the service type suffix from the instance name
	name := strings.TrimSuffix(instance, "."+serviceType)
	name = strings.TrimSuffix(name, ".")
	return name
}

func cleanServiceType(name string) string {
	// "_http._tcp.local" -> "_http._tcp"
	name = strings.TrimSuffix(name, ".local")
	name = strings.TrimSuffix(name, ".")
	return name
}

func deduplicateServices(services []MDNSService) []MDNSService {
	seen := make(map[string]bool)
	var unique []MDNSService
	for _, s := range services {
		key := s.Name + "|" + s.Type
		if !seen[key] {
			seen[key] = true
			unique = append(unique, s)
		}
	}
	return unique
}

func mergeMDNS(results []DNSResult, services []MDNSService) []DNSResult {
	// Try to match mDNS services to existing results by hostname
	hostMap := make(map[string]int) // hostname -> index in results
	for i, r := range results {
		if r.Hostname != "" {
			hostMap[strings.ToLower(r.Hostname)] = i
		}
	}

	var unmatched []MDNSService
	for _, svc := range services {
		hostname := strings.ToLower(svc.Hostname)
		if idx, ok := hostMap[hostname]; ok {
			results[idx].MDNSServices = append(results[idx].MDNSServices, svc)
		} else {
			unmatched = append(unmatched, svc)
		}
	}

	// Create a catch-all result for unmatched mDNS services
	if len(unmatched) > 0 {
		results = append(results, DNSResult{
			IP:           "mDNS",
			MDNSServices: unmatched,
		})
	}

	return results
}
