package docker

import (
	"context"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
)

type Container struct {
	Name          string   `json:"name"`
	Image         string   `json:"image"`
	Status        string   `json:"status"`
	Health        string   `json:"health,omitempty"`
	Ports         []Port   `json:"ports,omitempty"`
	Networks      []string `json:"networks,omitempty"`
	ComposeProject string  `json:"compose_project,omitempty"`
	ComposeService string  `json:"compose_service,omitempty"`
	Volumes       []string `json:"volumes,omitempty"`
	EnvNames      []string `json:"env_names,omitempty"`
	RestartPolicy string   `json:"restart_policy,omitempty"`
}

type Port struct {
	Host      uint16 `json:"host"`
	Container uint16 `json:"container"`
	Protocol  string `json:"protocol,omitempty"`
}

type Network struct {
	Name       string   `json:"name"`
	Driver     string   `json:"driver"`
	Subnet     string   `json:"subnet,omitempty"`
	Containers []string `json:"containers,omitempty"`
}

func Discover() ([]Container, []Network, error) {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, nil, err
	}
	defer cli.Close()

	// List containers
	containerList, err := cli.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return nil, nil, err
	}

	var containers []Container
	for _, c := range containerList {
		// Inspect for detailed info
		info, err := cli.ContainerInspect(ctx, c.ID)
		if err != nil {
			continue
		}

		cont := Container{
			Name:   strings.TrimPrefix(info.Name, "/"),
			Image:  info.Config.Image,
			Status: mapState(info.State),
		}

		// Health
		if info.State.Health != nil {
			cont.Health = info.State.Health.Status
		}

		// Ports
		for containerPort, bindings := range info.NetworkSettings.Ports {
			for _, binding := range bindings {
				if binding.HostPort != "" {
					cont.Ports = append(cont.Ports, Port{
						Host:      parsePort(binding.HostPort),
						Container: uint16(containerPort.Int()),
						Protocol:  containerPort.Proto(),
					})
				}
			}
		}

		// Networks
		for netName := range info.NetworkSettings.Networks {
			cont.Networks = append(cont.Networks, netName)
		}

		// Compose labels
		if proj, ok := info.Config.Labels["com.docker.compose.project"]; ok {
			cont.ComposeProject = proj
		}
		if svc, ok := info.Config.Labels["com.docker.compose.service"]; ok {
			cont.ComposeService = svc
		}

		// Volumes (paths only)
		for _, mount := range info.Mounts {
			cont.Volumes = append(cont.Volumes, mount.Source+":"+mount.Destination)
		}

		// Env var NAMES only — never values
		for _, env := range info.Config.Env {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) > 0 {
				cont.EnvNames = append(cont.EnvNames, parts[0])
			}
		}

		// Restart policy
		cont.RestartPolicy = string(info.HostConfig.RestartPolicy.Name)

		containers = append(containers, cont)
	}

	// List networks
	networkList, err := cli.NetworkList(ctx, network.ListOptions{})
	if err != nil {
		return containers, nil, nil
	}

	var networks []Network
	for _, n := range networkList {
		// Skip default networks
		if n.Name == "bridge" || n.Name == "host" || n.Name == "none" {
			continue
		}

		net := Network{
			Name:   n.Name,
			Driver: n.Driver,
		}

		// Subnet
		if len(n.IPAM.Config) > 0 {
			net.Subnet = n.IPAM.Config[0].Subnet
		}

		// Connected containers
		for _, ep := range n.Containers {
			net.Containers = append(net.Containers, ep.Name)
		}

		networks = append(networks, net)
	}

	return containers, networks, nil
}

func mapState(state *types.ContainerState) string {
	if state.Running {
		return "running"
	}
	if state.Paused {
		return "paused"
	}
	if state.Restarting {
		return "restarting"
	}
	return "stopped"
}

func parsePort(s string) uint16 {
	var port uint16
	for _, c := range s {
		if c >= '0' && c <= '9' {
			port = port*10 + uint16(c-'0')
		}
	}
	return port
}
