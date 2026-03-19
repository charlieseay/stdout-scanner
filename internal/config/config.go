package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config holds all scanner settings, written by `init` and read by `scan`.
type Config struct {
	StdOut    StdOutConfig  `yaml:"stdout"`
	Modules   ModulesConfig `yaml:"modules"`
	Network   NetworkConfig `yaml:"network,omitempty"`
	Schedule  string        `yaml:"schedule,omitempty"`
	StateFile string        `yaml:"state_file,omitempty"`
}

type StdOutConfig struct {
	URL   string `yaml:"url"`
	Token string `yaml:"token"`
}

type ModulesConfig struct {
	Docker  bool `yaml:"docker"`
	Metrics bool `yaml:"metrics"`
	Network bool `yaml:"network"`
	DNS     bool `yaml:"dns"`
	Auth    bool `yaml:"auth"`
}

type NetworkConfig struct {
	Subnets []string `yaml:"subnets,omitempty"`
}

// DefaultPath returns the default config file location.
// Inside Docker: /data/scanner.yaml
// On host: ~/.stdout/scanner.yaml
func DefaultPath() string {
	// If /data exists and is writable, prefer it (Docker)
	if info, err := os.Stat("/data"); err == nil && info.IsDir() {
		return "/data/scanner.yaml"
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "scanner.yaml"
	}
	return filepath.Join(home, ".stdout", "scanner.yaml")
}

// Load reads config from a YAML file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Save writes config to a YAML file, creating parent directories as needed.
func (c *Config) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// Defaults returns a config with sensible defaults.
func Defaults() *Config {
	return &Config{
		Modules: ModulesConfig{
			Docker:  true,
			Metrics: true,
		},
		StateFile: "/data/last-scan.json",
	}
}
