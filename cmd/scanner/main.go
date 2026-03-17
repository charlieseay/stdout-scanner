package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/charlieseay/stdout-scanner/internal/api"
	"github.com/charlieseay/stdout-scanner/internal/docker"
	"github.com/charlieseay/stdout-scanner/internal/host"
	"github.com/charlieseay/stdout-scanner/internal/output"
)

var (
	version = "dev"
)

func main() {
	token := flag.String("token", "", "StdOut API token (required for push)")
	url := flag.String("url", "", "StdOut instance URL (required for push)")
	outputMode := flag.String("output", "", "Output mode: json, markdown, or empty to push to StdOut")
	skipHost := flag.Bool("skip-host", false, "Skip host info collection")
	dryRun := flag.Bool("dry-run", false, "Discover but don't push to StdOut")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("stdout-scanner %s\n", version)
		os.Exit(0)
	}

	// Discover Docker containers
	fmt.Fprintln(os.Stderr, "Discovering Docker containers...")
	containers, networks, err := docker.Discover()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Docker discovery failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Found %d containers, %d networks\n", len(containers), len(networks))

	// Collect host info
	var hostInfo *host.Info
	if !*skipHost {
		fmt.Fprintln(os.Stderr, "Collecting host info...")
		hostInfo = host.Collect()
	}

	// Build scan result
	scan := output.ScanResult{
		Version:    "1",
		ScannedAt:  output.Now(),
		Host:       hostInfo,
		Containers: containers,
		Networks:   networks,
	}

	// Output mode
	switch *outputMode {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(scan)
		return
	case "markdown":
		fmt.Print(output.RenderMarkdown(scan))
		return
	}

	// Push to StdOut
	if *dryRun {
		fmt.Fprintln(os.Stderr, "Dry run — not pushing to StdOut")
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(scan)
		return
	}

	if *token == "" || *url == "" {
		fmt.Fprintln(os.Stderr, "Error: --token and --url are required (or use --output json/markdown)")
		flag.Usage()
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, "Pushing results to StdOut...")
	result, err := api.Push(*url, *token, scan)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Push failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Import created: %s\n", result.ImportID)
	fmt.Fprintf(os.Stderr, "Review at: %s%s\n", *url, result.ReviewURL)
}
