package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

// ContainerMetrics holds point-in-time resource usage for a single container.
type ContainerMetrics struct {
	Name          string  `json:"name"`
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryUsed    uint64  `json:"memory_used_bytes"`
	MemoryLimit   uint64  `json:"memory_limit_bytes"`
	MemoryPercent float64 `json:"memory_percent"`
	NetRxBytes    uint64  `json:"net_rx_bytes"`
	NetTxBytes    uint64  `json:"net_tx_bytes"`
	BlockRead     uint64  `json:"block_read_bytes"`
	BlockWrite    uint64  `json:"block_write_bytes"`
	PIDs          uint64  `json:"pids"`
}

// CollectContainers gathers resource metrics for all running containers.
// Uses Docker's one-shot stats API (stream=false) which returns a single
// snapshot including both current and previous CPU counters for percentage
// calculation.
func CollectContainers() ([]ContainerMetrics, error) {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("docker client: %w", err)
	}
	defer cli.Close()

	// Only collect from running containers
	containers, err := cli.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}

	var results []ContainerMetrics
	for _, c := range containers {
		name := c.Names[0]
		if len(name) > 0 && name[0] == '/' {
			name = name[1:]
		}

		m, err := collectOne(ctx, cli, c.ID, name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  metrics skip %s: %v\n", name, err)
			continue
		}
		results = append(results, *m)
	}

	return results, nil
}

func collectOne(ctx context.Context, cli *client.Client, id, name string) (*ContainerMetrics, error) {
	resp, err := cli.ContainerStats(ctx, id, false)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var stats container.StatsResponse
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return nil, err
	}

	m := &ContainerMetrics{
		Name:       name,
		MemoryUsed: stats.MemoryStats.Usage,
	}

	// Memory limit and percentage
	if stats.MemoryStats.Limit > 0 {
		m.MemoryLimit = stats.MemoryStats.Limit
		m.MemoryPercent = float64(stats.MemoryStats.Usage) / float64(stats.MemoryStats.Limit) * 100.0
	}

	// CPU percentage from delta between current and previous readings
	cpuDelta := float64(stats.CPUStats.CPUUsage.TotalUsage - stats.PreCPUStats.CPUUsage.TotalUsage)
	systemDelta := float64(stats.CPUStats.SystemUsage - stats.PreCPUStats.SystemUsage)
	if systemDelta > 0 && stats.CPUStats.OnlineCPUs > 0 {
		m.CPUPercent = (cpuDelta / systemDelta) * float64(stats.CPUStats.OnlineCPUs) * 100.0
	}

	// Network I/O (sum across all interfaces)
	for _, netStats := range stats.Networks {
		m.NetRxBytes += netStats.RxBytes
		m.NetTxBytes += netStats.TxBytes
	}

	// Block I/O
	for _, bio := range stats.BlkioStats.IoServiceBytesRecursive {
		switch bio.Op {
		case "read", "Read":
			m.BlockRead += bio.Value
		case "write", "Write":
			m.BlockWrite += bio.Value
		}
	}

	// PIDs
	m.PIDs = stats.PidsStats.Current

	return m, nil
}
