package host

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/docker/docker/client"
)

type Info struct {
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	CPUCores int    `json:"cpu_cores"`
	MemoryGB float64 `json:"memory_gb,omitempty"`
	Disk     []Disk `json:"disk,omitempty"`
}

type Disk struct {
	Mount   string  `json:"mount"`
	TotalGB float64 `json:"total_gb"`
	UsedGB  float64 `json:"used_gb"`
}

func Collect() *Info {
	info := &Info{
		Arch:     runtime.GOARCH,
		CPUCores: runtime.NumCPU(),
	}

	// OS version
	info.OS = detectOS()

	// Memory
	info.MemoryGB = detectMemory()

	// Disk
	info.Disk = detectDisk()

	return info
}

func detectOS() string {
	// If running inside Docker, ask the Docker daemon for the real host OS.
	// The container's /etc/os-release is Alpine (the scanner image), not the host.
	if isInContainer() {
		if hostOS := detectHostOSViaDocker(); hostOS != "" {
			return hostOS
		}
	}

	// Try /etc/os-release (Linux — accurate when not containerized)
	data, err := os.ReadFile("/etc/os-release")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				name := strings.TrimPrefix(line, "PRETTY_NAME=")
				name = strings.Trim(name, "\"")
				return name
			}
		}
	}

	// Fallback: uname
	out, err := exec.Command("uname", "-sr").Output()
	if err == nil {
		return strings.TrimSpace(string(out))
	}

	return runtime.GOOS
}

// isInContainer checks if we're running inside a Docker container.
func isInContainer() bool {
	_, err := os.Stat("/.dockerenv")
	return err == nil
}

// detectHostOSViaDocker uses the Docker API to get the actual host OS.
func detectHostOSViaDocker() string {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return ""
	}
	defer cli.Close()

	info, err := cli.Info(context.Background())
	if err != nil {
		return ""
	}

	// Docker info gives us OperatingSystem (e.g. "Docker Desktop", "Ubuntu 24.04")
	// and KernelVersion (e.g. "6.10.14-linuxkit")
	os := info.OperatingSystem
	if os == "" {
		os = info.OSType // "linux", "windows"
	}

	// Enrich with kernel version if available
	if info.KernelVersion != "" && !strings.Contains(os, info.KernelVersion) {
		os += " (" + info.KernelVersion + ")"
	}

	return os
}

func detectMemory() float64 {
	// Try /proc/meminfo (Linux)
	data, err := os.ReadFile("/proc/meminfo")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					kb, _ := strconv.ParseFloat(fields[1], 64)
					return kb / 1024 / 1024 // KB to GB
				}
			}
		}
	}

	// macOS: sysctl
	out, err := exec.Command("sysctl", "-n", "hw.memsize").Output()
	if err == nil {
		bytes, _ := strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
		return bytes / 1024 / 1024 / 1024
	}

	return 0
}

func detectDisk() []Disk {
	out, err := exec.Command("df", "-k", "/").Output()
	if err != nil {
		return nil
	}

	lines := strings.Split(string(out), "\n")
	if len(lines) < 2 {
		return nil
	}

	fields := strings.Fields(lines[1])
	if len(fields) < 4 {
		return nil
	}

	totalKB, _ := strconv.ParseFloat(fields[1], 64)
	usedKB, _ := strconv.ParseFloat(fields[2], 64)

	return []Disk{{
		Mount:   "/",
		TotalGB: totalKB / 1024 / 1024,
		UsedGB:  usedKB / 1024 / 1024,
	}}
}
