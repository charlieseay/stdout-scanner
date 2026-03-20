package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/charlieseay/stdout-scanner/internal/api"
	"github.com/charlieseay/stdout-scanner/internal/config"
	"github.com/charlieseay/stdout-scanner/internal/credentials"
	"github.com/charlieseay/stdout-scanner/internal/delta"
	"github.com/charlieseay/stdout-scanner/internal/docker"
	"github.com/charlieseay/stdout-scanner/internal/host"
	"github.com/charlieseay/stdout-scanner/internal/metrics"
	"github.com/charlieseay/stdout-scanner/internal/network"
	"github.com/charlieseay/stdout-scanner/internal/output"
	"github.com/charlieseay/stdout-scanner/internal/schedule"
)

var (
	version = "dev"
)

func main() {
	if len(os.Args) < 2 {
		runScan(os.Args[1:])
		return
	}

	// Route subcommands. If first arg starts with "-", treat as scan flags
	// for backward compatibility with v1 CLI.
	switch {
	case os.Args[1] == "init":
		runInit(os.Args[2:])
	case os.Args[1] == "scan":
		runScan(os.Args[2:])
	case os.Args[1] == "version":
		fmt.Printf("stdout-scanner %s\n", version)
	case strings.HasPrefix(os.Args[1], "-"):
		runScan(os.Args[1:])
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		fmt.Fprintln(os.Stderr, "Usage: stdout-scanner [init|scan|version] [flags]")
		os.Exit(1)
	}
}

// runInit runs the interactive setup interview.
func runInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	configPath := fs.String("config", "", "Config file path (default: auto-detected)")
	fs.Parse(args)

	if *configPath == "" {
		*configPath = config.DefaultPath()
	}

	// Check if stdin is a terminal
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) == 0 {
		fmt.Fprintln(os.Stderr, "Error: init requires an interactive terminal.")
		fmt.Fprintln(os.Stderr, "If running in Docker, use: docker run -it ...")
		os.Exit(1)
	}

	cfg, err := config.RunInterview()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Setup failed: %v\n", err)
		os.Exit(1)
	}

	if err := cfg.Save(*configPath); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to save config: %v\n", err)
		os.Exit(1)
	}

	config.PrintPostSetup(*configPath)
}

// runScan performs the actual infrastructure scan.
func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	token := fs.String("token", "", "StdOut API token (overrides config)")
	url := fs.String("url", "", "StdOut instance URL (overrides config)")
	outputMode := fs.String("output", "", "Output mode: json, markdown, or empty to push to StdOut")
	configPath := fs.String("config", "", "Config file path (default: auto-detected)")
	skipHost := fs.Bool("skip-host", false, "Skip host info collection")
	skipMetrics := fs.Bool("skip-metrics", false, "Skip resource metrics collection")
	scanNetwork := fs.Bool("scan-network", false, "Enable network device discovery (overrides config)")
	subnets := fs.String("subnets", "", "Subnet(s) to scan, comma-separated (e.g. 192.168.0.0/24)")
	scanSNMP := fs.Bool("scan-snmp", true, "Attempt SNMP queries on discovered devices")
	scanDNS := fs.Bool("scan-dns", false, "Enable DNS/service discovery (overrides config)")
	scanAuth := fs.Bool("scan-auth", false, "Enable auth detection (overrides config)")
	fullScan := fs.Bool("full", false, "Enable all discovery modules")
	deltaMode := fs.Bool("delta", false, "Compare against previous scan, report changes only")
	stateFile := fs.String("state-file", "", "Path to store previous scan for delta (default: from config)")
	scheduleFlag := fs.String("schedule", "", "Run on schedule: hourly, daily, daily@03:00, weekly@sun@03:00")
	webhookURL := fs.String("webhook", "", "POST scan results to this URL (generic webhook)")
	saveTo := fs.String("save-to", "", "Save scan results to this JSON file")
	scanTargets := fs.String("scan-targets", "", "Filter discovered hosts: all, servers, endpoints (default: all)")
	credentialsFile := fs.String("credentials-file", "", "Path to YAML credentials config for SNMP/SSH")
	dryRun := fs.Bool("dry-run", false, "Discover but don't push")
	showVersion := fs.Bool("version", false, "Print version and exit")
	fs.Parse(args)

	if *showVersion {
		fmt.Printf("stdout-scanner %s\n", version)
		os.Exit(0)
	}

	// Load config (optional — CLI flags override)
	var cfg *config.Config
	if *configPath == "" {
		*configPath = config.DefaultPath()
	}
	if loaded, err := config.Load(*configPath); err == nil {
		cfg = loaded
		fmt.Fprintf(os.Stderr, "Loaded config: %s\n", *configPath)
	} else {
		cfg = config.Defaults()
	}

	// CLI flags override config
	if *token != "" {
		cfg.StdOut.Token = *token
	}
	if *url != "" {
		cfg.StdOut.URL = *url
	}
	if *skipMetrics {
		cfg.Modules.Metrics = false
	}
	if *fullScan {
		cfg.Modules.Docker = true
		cfg.Modules.Metrics = true
		cfg.Modules.Network = true
		cfg.Modules.DNS = true
		cfg.Modules.Auth = true
	}
	if *scanNetwork {
		cfg.Modules.Network = true
	}
	if *scanDNS {
		cfg.Modules.DNS = true
		cfg.Modules.Network = true // DNS requires network scan first
	}
	if *scanAuth {
		cfg.Modules.Auth = true
		cfg.Modules.Network = true // Auth requires network scan first
	}
	if *webhookURL != "" {
		cfg.Targets = append(cfg.Targets, config.TargetConfig{
			Name: "cli-webhook",
			URL:  *webhookURL,
		})
	}
	if *saveTo != "" {
		cfg.OutputFile = *saveTo
	}
	if *subnets != "" {
		cfg.Modules.Network = true
		cfg.Network.Subnets = strings.Split(*subnets, ",")
		for i := range cfg.Network.Subnets {
			cfg.Network.Subnets[i] = strings.TrimSpace(cfg.Network.Subnets[i])
		}
	}

	// Apply scan-targets override
	if *scanTargets != "" {
		switch *scanTargets {
		case "all", "servers", "endpoints":
			cfg.Network.TargetFilter = *scanTargets
		default:
			fmt.Fprintf(os.Stderr, "Invalid --scan-targets value %q (use all, servers, or endpoints)\n", *scanTargets)
			os.Exit(1)
		}
	}
	if cfg.Network.TargetFilter == "" {
		cfg.Network.TargetFilter = "all"
	}

	// Load credentials
	credsPath := *credentialsFile
	if credsPath == "" {
		credsPath = cfg.Network.CredentialsFile
	}
	var credStore *credentials.Store
	if credsPath != "" {
		var err error
		credStore, err = credentials.LoadFile(credsPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load credentials: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Loaded credentials: %s (%d SNMP, %d SSH)\n",
			credsPath, len(credStore.SNMP), len(credStore.SSH))
	} else {
		credStore = credentials.DefaultStore()
	}

	// Track which modules ran
	var modules []string

	// Discover Docker containers
	var containers []docker.Container
	var networks []docker.Network
	if cfg.Modules.Docker {
		fmt.Fprintln(os.Stderr, "Discovering Docker containers...")
		var err error
		containers, networks, err = docker.Discover()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Docker discovery failed: %v (continuing without container data)\n", err)
			// Non-fatal — network scan and other modules can still run
		}
		fmt.Fprintf(os.Stderr, "Found %d containers, %d networks\n", len(containers), len(networks))
		modules = append(modules, "docker")
	}

	// Collect host info
	var hostInfo *host.Info
	if !*skipHost {
		fmt.Fprintln(os.Stderr, "Collecting host info...")
		hostInfo = host.Collect()
	}

	// Collect metrics
	var containerMetrics []metrics.ContainerMetrics
	var hostMetrics *metrics.HostMetrics
	if cfg.Modules.Metrics {
		fmt.Fprintln(os.Stderr, "Collecting resource metrics...")

		hostMetrics = metrics.CollectHost()
		fmt.Fprintf(os.Stderr, "  Host: CPU %.1f%%, Memory %.1f/%.1f GB (%.1f%%)\n",
			hostMetrics.CPUPercent, hostMetrics.MemoryUsedGB, hostMetrics.MemoryTotalGB, hostMetrics.MemoryPercent)

		if cfg.Modules.Docker {
			var err error
			containerMetrics, err = metrics.CollectContainers()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Container metrics failed: %v\n", err)
				// Non-fatal — continue without container metrics
			} else {
				fmt.Fprintf(os.Stderr, "  Collected metrics for %d containers\n", len(containerMetrics))

				// Flag resource hogs
				for _, m := range containerMetrics {
					if m.MemoryPercent > 80 {
						fmt.Fprintf(os.Stderr, "  ⚠ %s using %.1f%% memory (%s/%s)\n",
							m.Name, m.MemoryPercent,
							formatBytesShort(m.MemoryUsed), formatBytesShort(m.MemoryLimit))
					}
					if m.CPUPercent > 80 {
						fmt.Fprintf(os.Stderr, "  ⚠ %s using %.1f%% CPU\n", m.Name, m.CPUPercent)
					}
				}
			}
		}
		modules = append(modules, "metrics")
	}

	// Network device discovery
	var networkDevices []network.ScanResult
	if cfg.Modules.Network {
		// Determine subnets to scan
		scanSubnets := cfg.Network.Subnets
		if len(scanSubnets) == 0 {
			if detected := network.DetectSubnet(); detected != "" {
				scanSubnets = []string{detected}
				fmt.Fprintf(os.Stderr, "Auto-detected subnet: %s\n", detected)
			} else {
				fmt.Fprintln(os.Stderr, "Network scan: no subnet detected or configured, skipping")
			}
		}

		opts := network.ScanOptions{
			ScanPorts:    true,
			ScanSNMP:     *scanSNMP,
			TargetFilter: cfg.Network.TargetFilter,
			Credentials:  credStore,
		}

		ctx := context.Background()
		for _, subnet := range scanSubnets {
			fmt.Fprintf(os.Stderr, "Scanning network %s...\n", subnet)
			result, err := network.ScanSubnet(ctx, subnet, opts)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Network scan %s failed: %v\n", subnet, err)
				continue
			}
			fmt.Fprintf(os.Stderr, "  Found %d devices on %s\n", len(result.Devices), subnet)
			networkDevices = append(networkDevices, *result)
		}
		modules = append(modules, "network")
	}

	// Collect all discovered devices (from all subnet scans) for DNS/auth
	var allDevices []network.Device
	for _, ns := range networkDevices {
		allDevices = append(allDevices, ns.Devices...)
	}

	// DNS & service discovery
	var dnsResults []network.DNSResult
	if cfg.Modules.DNS && len(allDevices) > 0 {
		fmt.Fprintln(os.Stderr, "Running DNS & service discovery...")
		ctx := context.Background()
		dnsResults = network.DiscoverDNS(ctx, allDevices)
		fmt.Fprintf(os.Stderr, "  DNS results for %d hosts\n", len(dnsResults))
		modules = append(modules, "dns")
	}

	// Auth detection
	var authResults []network.AuthResult
	if cfg.Modules.Auth && len(allDevices) > 0 {
		fmt.Fprintln(os.Stderr, "Detecting authentication...")
		ctx := context.Background()
		authResults = network.DetectAuth(ctx, allDevices)
		fmt.Fprintf(os.Stderr, "  Auth checked %d hosts\n", len(authResults))
		modules = append(modules, "auth")
	}

	// Build scan result
	scan := output.ScanResult{
		Version:          "2",
		ScannedAt:        output.Now(),
		Modules:          modules,
		Host:             hostInfo,
		HostMetrics:      hostMetrics,
		Containers:       containers,
		ContainerMetrics: containerMetrics,
		Networks:         networks,
		NetworkDevices:   networkDevices,
		DNSResults:       dnsResults,
		AuthResults:      authResults,
	}

	// Resolve state file path
	statePath := cfg.StateFile
	if *stateFile != "" {
		statePath = *stateFile
	}
	if statePath == "" {
		statePath = "/data/last-scan.json"
	}

	// Delta comparison
	if *deltaMode {
		prev, err := delta.LoadState(statePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "No previous scan at %s — running as full scan\n", statePath)
		} else {
			diff := delta.Compare(*prev, scan)
			fmt.Fprintf(os.Stderr, "Delta: %s\n", delta.RenderOneLiner(diff))

			// Save current scan as new state
			if err := delta.SaveState(statePath, scan); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to save state: %v\n", err)
			}

			// Output delta
			switch *outputMode {
			case "json":
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				enc.Encode(diff)
				return
			case "markdown":
				fmt.Print(delta.RenderMarkdown(diff))
				return
			default:
				// Push delta if configured and changes exist
				if !*dryRun && diff.HasChanges() && cfg.HasTargets() {
					pushToTargets(scan, cfg)
				} else if *dryRun {
					enc := json.NewEncoder(os.Stdout)
					enc.SetIndent("", "  ")
					enc.Encode(diff)
				} else if !diff.HasChanges() {
					fmt.Fprintln(os.Stderr, "No changes — nothing to push")
				}
				return
			}
		}
	}

	// Save state for future delta comparisons
	if err := delta.SaveState(statePath, scan); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to save state: %v\n", err)
	}

	// Handle scheduled mode — wraps the scan in a loop
	if *scheduleFlag != "" {
		sched, err := schedule.ParseSchedule(*scheduleFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid schedule: %v\n", err)
			os.Exit(1)
		}

		// For scheduled mode, output the first scan then enter the loop
		emitScan(scan, *outputMode, *dryRun, cfg)

		ctx := context.Background()
		schedule.Run(ctx, sched, cfg.StdOut.URL, cfg.StdOut.Token, func() {
			// Re-run the scan as a delta
			fmt.Fprintln(os.Stderr, "--- Scheduled scan ---")
			// We can't easily re-run all the discovery here without
			// refactoring into a scanOnce function. For now, the scheduler
			// simply re-executes the binary with --delta.
			// In practice, users will run:
			//   stdout-scanner scan --schedule daily --delta
			// which means each iteration compares against the previous.
		})
		return
	}

	// One-shot output
	emitScan(scan, *outputMode, *dryRun, cfg)
}

// emitScan handles outputting or pushing a scan result.
func emitScan(scan output.ScanResult, outputMode string, dryRun bool, cfg *config.Config) {
	switch outputMode {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(scan)
		return
	case "markdown":
		fmt.Print(output.RenderMarkdown(scan))
		return
	}

	if dryRun {
		fmt.Fprintln(os.Stderr, "Dry run — not pushing")
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(scan)
		return
	}

	if !cfg.HasTargets() {
		fmt.Fprintln(os.Stderr, "No targets configured. Use --output json/markdown, --webhook, --save-to, or --token/--url.")
		fmt.Fprintln(os.Stderr, "Run 'stdout-scanner init' to configure targets.")
		os.Exit(1)
	}

	pushToTargets(scan, cfg)
}

// pushToTargets sends scan results to all configured targets.
func pushToTargets(scan output.ScanResult, cfg *config.Config) {
	// StdOut integration
	if cfg.StdOut.URL != "" && cfg.StdOut.Token != "" {
		target := api.StdOutTarget(cfg.StdOut.URL, cfg.StdOut.Token)
		fmt.Fprintf(os.Stderr, "Pushing to StdOut (%s)...\n", cfg.StdOut.URL)
		result, err := api.Push(target, scan)
		if err != nil {
			fmt.Fprintf(os.Stderr, "StdOut push failed: %v\n", err)
		} else if result.ImportID != "" {
			fmt.Fprintf(os.Stderr, "Import created: %s\n", result.ImportID)
			fmt.Fprintf(os.Stderr, "Review at: %s%s\n", cfg.StdOut.URL, result.ReviewURL)
		} else {
			fmt.Fprintf(os.Stderr, "Push OK (%d)\n", result.StatusCode)
		}
	}

	// Generic webhook targets
	for _, t := range cfg.Targets {
		target := api.WebhookTarget(t.URL, t.Token, t.Headers)
		target.Insecure = t.Insecure
		label := t.Name
		if label == "" {
			label = t.URL
		}
		fmt.Fprintf(os.Stderr, "Pushing to %s...\n", label)
		result, err := api.Push(target, scan)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Webhook %s failed: %v\n", label, err)
		} else {
			fmt.Fprintf(os.Stderr, "Webhook %s OK (%d)\n", label, result.StatusCode)
		}
	}

	// File output
	if cfg.OutputFile != "" {
		fmt.Fprintf(os.Stderr, "Saving to %s...\n", cfg.OutputFile)
		if err := api.PushToFile(cfg.OutputFile, scan); err != nil {
			fmt.Fprintf(os.Stderr, "File save failed: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "Saved.\n")
		}
	}
}

func formatBytesShort(b uint64) string {
	const (
		kb = 1024
		mb = kb * 1024
		gb = mb * 1024
	)
	switch {
	case b >= gb:
		return fmt.Sprintf("%.1fGB", float64(b)/float64(gb))
	case b >= mb:
		return fmt.Sprintf("%.0fMB", float64(b)/float64(mb))
	default:
		return fmt.Sprintf("%.0fKB", float64(b)/float64(kb))
	}
}
