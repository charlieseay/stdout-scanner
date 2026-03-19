package config

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

// ANSI color helpers
const (
	bold   = "\033[1m"
	dim    = "\033[2m"
	green  = "\033[32m"
	red    = "\033[31m"
	yellow = "\033[33m"
	cyan   = "\033[36m"
	reset  = "\033[0m"
)

// Capability represents a detected system capability.
type Capability struct {
	Name    string
	Found   bool
	Detail  string
	HowTo   string // how to grant access if not found
}

// RunInterview runs the interactive setup flow and returns a Config.
func RunInterview() (*Config, error) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println()
	fmt.Printf("%s  stdout-scanner setup%s\n", bold, reset)
	fmt.Printf("  %s────────────────────%s\n", dim, reset)
	fmt.Println()

	// Phase 1: Detect capabilities
	fmt.Printf("  %sDetecting your environment...%s\n\n", dim, reset)
	caps := detectCapabilities()
	for _, cap := range caps {
		if cap.Found {
			fmt.Printf("  %s✓%s %s — %s\n", green, reset, cap.Name, cap.Detail)
		} else {
			fmt.Printf("  %s✗%s %s — %s\n", red, reset, cap.Name, cap.Detail)
			if cap.HowTo != "" {
				fmt.Printf("    %s%s%s\n", dim, cap.HowTo, reset)
			}
		}
	}
	fmt.Println()

	cfg := Defaults()

	// Phase 2: Module selection
	fmt.Printf("  %sWhat should I scan?%s\n\n", bold, reset)

	dockerAvail := capFound(caps, "Docker socket")
	if dockerAvail {
		cfg.Modules.Docker = askYesNo(reader, "Docker containers", true)
		cfg.Modules.Metrics = askYesNo(reader, "Resource metrics (CPU, memory, disk per container + host)", true)
	} else {
		fmt.Printf("  %sDocker not available — skipping container and metrics modules%s\n", dim, reset)
		cfg.Modules.Docker = false
		cfg.Modules.Metrics = false
	}

	netAvail := capFound(caps, "Network scanning")
	if netAvail {
		cfg.Modules.Network = askYesNo(reader, "Network devices (ARP/ICMP scan of local subnet)", false)
		if cfg.Modules.Network {
			subnet := capDetail(caps, "Network scanning")
			cfg.Network.Subnets = askSubnets(reader, subnet)
			cfg.Modules.DNS = askYesNo(reader, "DNS & service discovery (mDNS, reverse proxy, SSL certs)", false)
			cfg.Modules.Auth = askYesNo(reader, "Auth detection (identify login-gated services)", false)
		}
	} else {
		fmt.Printf("  %sNetwork scanning not available — see above for how to enable%s\n", dim, reset)
		cfg.Modules.Network = false
		cfg.Modules.DNS = false
		cfg.Modules.Auth = false
	}

	fmt.Println()

	// Phase 3: Output target
	fmt.Printf("  %sOutput target%s\n", bold, reset)
	fmt.Printf("  %s─────────────%s\n", dim, reset)
	fmt.Println()
	fmt.Printf("  %sWhere should scan results be sent?%s\n", dim, reset)
	fmt.Println()
	fmt.Printf("  %s1)%s StdOut (incident companion — push to your StdOut instance)\n", cyan, reset)
	fmt.Printf("  %s2)%s Webhook (POST JSON to any URL)\n", cyan, reset)
	fmt.Printf("  %s3)%s File (save JSON to disk)\n", cyan, reset)
	fmt.Printf("  %s4)%s None (local output only — use --output json/markdown)\n", cyan, reset)
	fmt.Println()

	targetChoice := askString(reader, "Target [1/2/3/4]", "4")

	switch targetChoice {
	case "1":
		// StdOut integration
		cfg.StdOut.URL = askString(reader, "StdOut instance URL", "")
		if cfg.StdOut.URL != "" {
			cfg.StdOut.URL = strings.TrimRight(cfg.StdOut.URL, "/")
			fmt.Println()
			fmt.Printf("  %sHow do you want to authenticate?%s\n", bold, reset)
			fmt.Printf("  %s1)%s Paste an existing API token\n", cyan, reset)
			fmt.Printf("  %s2)%s Create one in the browser at %s/app/settings\n", cyan, reset, cfg.StdOut.URL)
			fmt.Println()
			cfg.StdOut.Token = askString(reader, "API token", "")
			if cfg.StdOut.Token == "" {
				fmt.Printf("  %sNo token provided — you can add it later in the config file.%s\n", yellow, reset)
			}
		}

	case "2":
		// Generic webhook
		webhookURL := askString(reader, "Webhook URL (POST endpoint)", "")
		if webhookURL != "" {
			target := TargetConfig{
				Name: "webhook",
				URL:  webhookURL,
			}
			webhookToken := askString(reader, "Bearer token (optional)", "")
			if webhookToken != "" {
				target.Token = webhookToken
			}
			cfg.Targets = append(cfg.Targets, target)
		}

	case "3":
		// File output
		cfg.OutputFile = askString(reader, "Output file path", "/data/scan-results.json")

	default:
		fmt.Printf("  %sNo target configured — use --output json or --output markdown to view results.%s\n", dim, reset)
	}

	fmt.Println()

	// Phase 4: Scheduling
	fmt.Printf("  %sScheduling%s\n", bold, reset)
	fmt.Printf("  %s──────────%s\n", dim, reset)
	fmt.Println()
	fmt.Printf("  %sThe scanner can run on a schedule and report only changes (delta mode).%s\n", dim, reset)
	fmt.Println()

	if askYesNo(reader, "Enable scheduled scanning", false) {
		fmt.Println()
		fmt.Printf("  %s1)%s Daily (default: 3:00 AM)\n", cyan, reset)
		fmt.Printf("  %s2)%s Weekly\n", cyan, reset)
		fmt.Printf("  %s3)%s Hourly\n", cyan, reset)
		fmt.Println()
		choice := askString(reader, "Schedule [1/2/3]", "1")
		switch choice {
		case "2":
			cfg.Schedule = "weekly"
		case "3":
			cfg.Schedule = "hourly"
		default:
			cfg.Schedule = "daily"
		}
	}

	fmt.Println()
	return cfg, nil
}

// PrintPostSetup prints next-steps after config is saved.
func PrintPostSetup(configPath string) {
	fmt.Printf("  %s✓ Config saved to %s%s\n\n", green, configPath, reset)
	fmt.Printf("  %sNext steps:%s\n", bold, reset)
	fmt.Printf("  • Run %sstdout-scanner scan%s to scan now\n", cyan, reset)
	fmt.Printf("  • Run %sstdout-scanner scan --delta%s to compare against last scan\n", cyan, reset)
	fmt.Printf("  • Run %sstdout-scanner scan --schedule daily%s for recurring scans\n", cyan, reset)
	fmt.Printf("  • Edit %s%s%s to change settings\n", cyan, configPath, reset)
	fmt.Println()
}

// detectCapabilities probes the environment for available features.
func detectCapabilities() []Capability {
	var caps []Capability

	// Docker socket
	dockerCap := Capability{Name: "Docker socket"}
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err == nil {
		defer cli.Close()
		containers, err := cli.ContainerList(context.Background(), containerListOpts())
		if err == nil {
			running := 0
			for _, c := range containers {
				if c.State == "running" {
					running++
				}
			}
			dockerCap.Found = true
			dockerCap.Detail = fmt.Sprintf("accessible (%d containers, %d running)", len(containers), running)
		} else {
			dockerCap.Detail = fmt.Sprintf("socket found but API error: %v", err)
			dockerCap.HowTo = "Mount Docker socket: -v /var/run/docker.sock:/var/run/docker.sock:ro"
		}
	} else {
		dockerCap.Detail = "not accessible"
		dockerCap.HowTo = "Mount Docker socket: -v /var/run/docker.sock:/var/run/docker.sock:ro"
	}
	caps = append(caps, dockerCap)

	// Host metrics
	hostCap := Capability{Name: "Host metrics"}
	if _, err := os.ReadFile("/proc/meminfo"); err == nil {
		hostCap.Found = true
		hostCap.Detail = "/proc available"
	} else {
		// macOS or restricted
		hostCap.Found = true
		hostCap.Detail = "system commands available"
	}
	caps = append(caps, hostCap)

	// Network scanning
	netCap := Capability{Name: "Network scanning"}
	subnet := detectSubnet()
	if subnet != "" {
		netCap.Found = true
		netCap.Detail = fmt.Sprintf("detected subnet %s", subnet)
	} else {
		netCap.Detail = "no subnet detected"
		netCap.HowTo = "Run with --net=host or --cap-add NET_RAW for network discovery"
	}
	caps = append(caps, netCap)

	return caps
}

// detectSubnet finds the primary local subnet.
func detectSubnet() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}

	for _, iface := range ifaces {
		// Skip loopback, down, and virtual interfaces
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
			// Return the network CIDR
			masked := ipNet.IP.Mask(ipNet.Mask)
			ones, _ := ipNet.Mask.Size()
			return fmt.Sprintf("%s/%d", masked, ones)
		}
	}
	return ""
}

// containerListOpts returns options for listing all containers.
func containerListOpts() container.ListOptions {
	return container.ListOptions{All: true}
}

// askYesNo prompts for a yes/no answer with a default.
func askYesNo(reader *bufio.Reader, prompt string, defaultYes bool) bool {
	hint := "y/N"
	if defaultYes {
		hint = "Y/n"
	}
	fmt.Printf("  %s [%s]: ", prompt, hint)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(strings.ToLower(input))

	if input == "" {
		return defaultYes
	}
	return input == "y" || input == "yes"
}

// askString prompts for a string value.
func askString(reader *bufio.Reader, prompt, defaultVal string) string {
	if defaultVal != "" {
		fmt.Printf("  %s [%s]: ", prompt, defaultVal)
	} else {
		fmt.Printf("  %s: ", prompt)
	}
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input == "" {
		return defaultVal
	}
	return input
}

// askSubnets asks the user to confirm or modify detected subnets.
func askSubnets(reader *bufio.Reader, detected string) []string {
	if detected != "" {
		fmt.Printf("  Subnet to scan [%s]: ", detected)
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)
		if input == "" {
			return []string{detected}
		}
		return parseSubnets(input)
	}

	fmt.Printf("  Subnet(s) to scan (comma-separated, e.g. 192.168.0.0/24): ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input == "" {
		return nil
	}
	return parseSubnets(input)
}

func parseSubnets(input string) []string {
	parts := strings.Split(input, ",")
	var subnets []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			subnets = append(subnets, p)
		}
	}
	return subnets
}

func capFound(caps []Capability, name string) bool {
	for _, c := range caps {
		if c.Name == name {
			return c.Found
		}
	}
	return false
}

func capDetail(caps []Capability, name string) string {
	for _, c := range caps {
		if c.Name == name {
			// Extract subnet from detail like "detected subnet 192.168.0.0/24"
			if strings.Contains(c.Detail, "detected subnet ") {
				return strings.TrimPrefix(c.Detail, "detected subnet ")
			}
			return c.Detail
		}
	}
	return ""
}
