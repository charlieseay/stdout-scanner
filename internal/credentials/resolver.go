package credentials

import (
	"fmt"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Store holds all credential entries loaded from a credentials file.
type Store struct {
	SNMP []SNMPCredential `yaml:"snmp"`
	SSH  []SSHCredential  `yaml:"ssh"`
}

// SNMPCredential defines credentials for SNMP access.
type SNMPCredential struct {
	// Version: "1", "2c", or "3"
	Version string `yaml:"version"`

	// v1/v2c fields
	Community string `yaml:"community,omitempty"`

	// v3 fields
	Username      string `yaml:"username,omitempty"`
	AuthProtocol  string `yaml:"auth_protocol,omitempty"`  // MD5, SHA, SHA-256, SHA-512
	AuthPassphrase string `yaml:"auth_passphrase,omitempty"`
	PrivProtocol  string `yaml:"priv_protocol,omitempty"`  // DES, AES, AES-192, AES-256
	PrivPassphrase string `yaml:"priv_passphrase,omitempty"`
	SecurityLevel string `yaml:"security_level,omitempty"` // noAuthNoPriv, authNoPriv, authPriv

	// Targeting — IPs, CIDRs, or "*" for all
	Targets []string `yaml:"targets"`
}

// SSHCredential defines credentials for SSH access.
type SSHCredential struct {
	Username string `yaml:"username"`
	Password string `yaml:"password,omitempty"`
	KeyFile  string `yaml:"key_file,omitempty"`
	Targets  []string `yaml:"targets"`
}

// LoadFile reads and parses a credentials YAML file.
func LoadFile(path string) (*Store, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading credentials file: %w", err)
	}

	var store Store
	if err := yaml.Unmarshal(data, &store); err != nil {
		return nil, fmt.Errorf("parsing credentials file: %w", err)
	}

	// Validate entries
	for i, cred := range store.SNMP {
		if err := validateSNMP(cred); err != nil {
			return nil, fmt.Errorf("snmp[%d]: %w", i, err)
		}
	}

	return &store, nil
}

func validateSNMP(c SNMPCredential) error {
	switch c.Version {
	case "1", "2c":
		if c.Community == "" {
			return fmt.Errorf("v%s requires community string", c.Version)
		}
	case "3":
		if c.Username == "" {
			return fmt.Errorf("v3 requires username")
		}
		switch c.SecurityLevel {
		case "noAuthNoPriv", "authNoPriv", "authPriv", "":
			// valid
		default:
			return fmt.Errorf("invalid security_level %q", c.SecurityLevel)
		}
		if c.SecurityLevel == "authNoPriv" || c.SecurityLevel == "authPriv" {
			if c.AuthProtocol == "" || c.AuthPassphrase == "" {
				return fmt.Errorf("security_level %q requires auth_protocol and auth_passphrase", c.SecurityLevel)
			}
		}
		if c.SecurityLevel == "authPriv" {
			if c.PrivProtocol == "" || c.PrivPassphrase == "" {
				return fmt.Errorf("security_level authPriv requires priv_protocol and priv_passphrase")
			}
		}
	default:
		return fmt.Errorf("invalid version %q (use 1, 2c, or 3)", c.Version)
	}
	if len(c.Targets) == 0 {
		return fmt.Errorf("at least one target is required")
	}
	return nil
}

// SNMPForHost returns all SNMP credentials that match the given IP,
// in file order (first match is tried first).
func (s *Store) SNMPForHost(ip string) []SNMPCredential {
	if s == nil {
		return nil
	}

	var matched []SNMPCredential
	for _, cred := range s.SNMP {
		if matchesTarget(ip, cred.Targets) {
			matched = append(matched, cred)
		}
	}
	return matched
}

// SSHForHost returns all SSH credentials that match the given IP.
func (s *Store) SSHForHost(ip string) []SSHCredential {
	if s == nil {
		return nil
	}

	var matched []SSHCredential
	for _, cred := range s.SSH {
		if matchesTarget(ip, cred.Targets) {
			matched = append(matched, cred)
		}
	}
	return matched
}

// matchesTarget checks if an IP matches any of the target specs.
// Supports: "*" (wildcard), individual IPs, CIDR ranges.
func matchesTarget(ip string, targets []string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	for _, target := range targets {
		target = strings.TrimSpace(target)

		if target == "*" {
			return true
		}

		// CIDR range
		if strings.Contains(target, "/") {
			_, cidr, err := net.ParseCIDR(target)
			if err != nil {
				continue
			}
			if cidr.Contains(parsedIP) {
				return true
			}
			continue
		}

		// Exact IP match
		if target == ip {
			return true
		}
	}

	return false
}

// DefaultStore returns a store with the traditional "public" community
// for SNMPv2c on all hosts. Used when no credentials file is specified.
func DefaultStore() *Store {
	return &Store{
		SNMP: []SNMPCredential{
			{
				Version:   "2c",
				Community: "public",
				Targets:   []string{"*"},
			},
		},
	}
}
