package metrics

import (
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// HostMetrics holds point-in-time resource usage for the host machine.
type HostMetrics struct {
	CPUPercent    float64    `json:"cpu_percent"`
	MemoryUsedGB  float64   `json:"memory_used_gb"`
	MemoryTotalGB float64   `json:"memory_total_gb"`
	MemoryPercent float64   `json:"memory_percent"`
	LoadAvg       [3]float64 `json:"load_avg"`
	Uptime        string    `json:"uptime"`
}

// CollectHost gathers point-in-time host resource metrics.
// Works on both Linux (/proc) and macOS (sysctl/vm_stat).
func CollectHost() *HostMetrics {
	m := &HostMetrics{}

	m.CPUPercent = measureCPU()
	collectMemory(m)
	m.LoadAvg = readLoadAvg()
	m.Uptime = readUptime()

	return m
}

// measureCPU takes two /proc/stat readings 1 second apart to calculate CPU%.
// On macOS, falls back to parsing `top -l 1`.
func measureCPU() float64 {
	if runtime.GOOS == "linux" {
		return measureCPULinux()
	}
	return measureCPUMac()
}

func measureCPULinux() float64 {
	read := func() (idle, total uint64) {
		data, err := os.ReadFile("/proc/stat")
		if err != nil {
			return 0, 0
		}
		lines := strings.Split(string(data), "\n")
		if len(lines) == 0 {
			return 0, 0
		}
		// First line: cpu <user> <nice> <system> <idle> <iowait> <irq> <softirq> <steal>
		fields := strings.Fields(lines[0])
		if len(fields) < 5 || fields[0] != "cpu" {
			return 0, 0
		}
		var vals []uint64
		for _, f := range fields[1:] {
			v, _ := strconv.ParseUint(f, 10, 64)
			vals = append(vals, v)
		}
		var sum uint64
		for _, v := range vals {
			sum += v
		}
		idleVal := uint64(0)
		if len(vals) >= 4 {
			idleVal = vals[3]
		}
		return idleVal, sum
	}

	idle1, total1 := read()
	time.Sleep(1 * time.Second)
	idle2, total2 := read()

	if total2 <= total1 {
		return 0
	}

	totalDelta := float64(total2 - total1)
	idleDelta := float64(idle2 - idle1)
	return ((totalDelta - idleDelta) / totalDelta) * 100.0
}

func measureCPUMac() float64 {
	// Parse `top -l 1 -n 0` for CPU usage
	out, err := exec.Command("top", "-l", "1", "-n", "0").Output()
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "CPU usage:") {
			// "CPU usage: 5.26% user, 10.52% sys, 84.21% idle"
			parts := strings.Split(line, ",")
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if strings.HasSuffix(p, "idle") {
					pct := strings.TrimSuffix(p, "% idle")
					pct = strings.TrimSpace(pct)
					idle, err := strconv.ParseFloat(pct, 64)
					if err == nil {
						return 100.0 - idle
					}
				}
			}
		}
	}
	return 0
}

func collectMemory(m *HostMetrics) {
	if runtime.GOOS == "linux" {
		collectMemoryLinux(m)
		return
	}
	collectMemoryMac(m)
}

func collectMemoryLinux(m *HostMetrics) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return
	}

	var totalKB, availKB float64
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		val, _ := strconv.ParseFloat(fields[1], 64)
		switch {
		case strings.HasPrefix(line, "MemTotal:"):
			totalKB = val
		case strings.HasPrefix(line, "MemAvailable:"):
			availKB = val
		}
	}

	if totalKB > 0 {
		m.MemoryTotalGB = totalKB / 1024 / 1024
		m.MemoryUsedGB = (totalKB - availKB) / 1024 / 1024
		m.MemoryPercent = ((totalKB - availKB) / totalKB) * 100.0
	}
}

func collectMemoryMac(m *HostMetrics) {
	// Total memory via sysctl
	out, err := exec.Command("sysctl", "-n", "hw.memsize").Output()
	if err != nil {
		return
	}
	totalBytes, _ := strconv.ParseFloat(strings.TrimSpace(string(out)), 64)
	m.MemoryTotalGB = totalBytes / 1024 / 1024 / 1024

	// Used memory via vm_stat
	out, err = exec.Command("vm_stat").Output()
	if err != nil {
		return
	}

	pageSize := 16384.0 // Apple Silicon default
	var active, wired, compressed float64
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "Mach Virtual Memory Statistics") {
			// Extract page size from header
			if idx := strings.Index(line, "page size of "); idx != -1 {
				rest := line[idx+len("page size of "):]
				rest = strings.TrimRight(rest, " bytes)")
				if ps, err := strconv.ParseFloat(rest, 64); err == nil {
					pageSize = ps
				}
			}
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		val := strings.TrimSpace(parts[1])
		val = strings.TrimRight(val, ".")
		pages, _ := strconv.ParseFloat(val, 64)

		switch strings.TrimSpace(parts[0]) {
		case "Pages active":
			active = pages
		case "Pages wired down":
			wired = pages
		case "Pages occupied by compressor":
			compressed = pages
		}
	}

	usedBytes := (active + wired + compressed) * pageSize
	m.MemoryUsedGB = usedBytes / 1024 / 1024 / 1024
	if m.MemoryTotalGB > 0 {
		m.MemoryPercent = (m.MemoryUsedGB / m.MemoryTotalGB) * 100.0
	}
}

func readLoadAvg() [3]float64 {
	var avg [3]float64

	if runtime.GOOS == "linux" {
		data, err := os.ReadFile("/proc/loadavg")
		if err != nil {
			return avg
		}
		fields := strings.Fields(string(data))
		if len(fields) >= 3 {
			avg[0], _ = strconv.ParseFloat(fields[0], 64)
			avg[1], _ = strconv.ParseFloat(fields[1], 64)
			avg[2], _ = strconv.ParseFloat(fields[2], 64)
		}
		return avg
	}

	// macOS
	out, err := exec.Command("sysctl", "-n", "vm.loadavg").Output()
	if err != nil {
		return avg
	}
	// Format: "{ 1.23 4.56 7.89 }"
	s := strings.Trim(strings.TrimSpace(string(out)), "{}")
	fields := strings.Fields(s)
	if len(fields) >= 3 {
		avg[0], _ = strconv.ParseFloat(fields[0], 64)
		avg[1], _ = strconv.ParseFloat(fields[1], 64)
		avg[2], _ = strconv.ParseFloat(fields[2], 64)
	}
	return avg
}

func readUptime() string {
	if runtime.GOOS == "linux" {
		data, err := os.ReadFile("/proc/uptime")
		if err != nil {
			return ""
		}
		fields := strings.Fields(string(data))
		if len(fields) >= 1 {
			secs, _ := strconv.ParseFloat(fields[0], 64)
			return formatDuration(time.Duration(secs) * time.Second)
		}
		return ""
	}

	// macOS: parse `sysctl kern.boottime`
	out, err := exec.Command("sysctl", "-n", "kern.boottime").Output()
	if err != nil {
		return ""
	}
	// Format: "{ sec = 1234567890, usec = 0 }"
	s := string(out)
	if idx := strings.Index(s, "sec = "); idx != -1 {
		rest := s[idx+6:]
		if end := strings.IndexByte(rest, ','); end != -1 {
			sec, _ := strconv.ParseInt(rest[:end], 10, 64)
			if sec > 0 {
				boot := time.Unix(sec, 0)
				return formatDuration(time.Since(boot))
			}
		}
	}
	return ""
}

func formatDuration(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60

	if days > 0 {
		return strconv.Itoa(days) + "d " + strconv.Itoa(hours) + "h " + strconv.Itoa(mins) + "m"
	}
	if hours > 0 {
		return strconv.Itoa(hours) + "h " + strconv.Itoa(mins) + "m"
	}
	return strconv.Itoa(mins) + "m"
}
