package network

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/charlieseay/stdout-scanner/internal/credentials"
	"github.com/gosnmp/gosnmp"
)

// SNMP OIDs for system MIB-2 (RFC 1213) — these are universal across
// all SNMP-capable devices.
var snmpOIDs = []string{
	"1.3.6.1.2.1.1.1.0", // sysDescr
	"1.3.6.1.2.1.1.3.0", // sysUpTime
	"1.3.6.1.2.1.1.4.0", // sysContact
	"1.3.6.1.2.1.1.5.0", // sysName
	"1.3.6.1.2.1.1.6.0", // sysLocation
}

var oidFieldMap = map[string]string{
	"1.3.6.1.2.1.1.1.0": "sysDescr",
	"1.3.6.1.2.1.1.3.0": "sysUpTime",
	"1.3.6.1.2.1.1.4.0": "sysContact",
	"1.3.6.1.2.1.1.5.0": "sysName",
	"1.3.6.1.2.1.1.6.0": "sysLocation",
}

// querySNMP attempts SNMP GET on the standard system OIDs using
// the provided credentials. Tries each matching credential in order;
// first successful response wins.
// Returns nil if the device doesn't respond to SNMP.
func querySNMP(ctx context.Context, ip string, creds []credentials.SNMPCredential) *SNMPInfo {
	if len(creds) == 0 {
		return nil
	}

	for _, cred := range creds {
		info := trySNMPCredential(ctx, ip, cred)
		if info != nil {
			fmt.Fprintf(os.Stderr, "    SNMP %s (v%s): %s (%s)\n", ip, cred.Version, info.SysName, info.SysDescr)
			return info
		}
	}

	return nil
}

// trySNMPCredential attempts to query a device with a single credential set.
func trySNMPCredential(ctx context.Context, ip string, cred credentials.SNMPCredential) *SNMPInfo {
	g := &gosnmp.GoSNMP{
		Target:    ip,
		Port:      161,
		Timeout:   2 * time.Second,
		Retries:   1,
		MaxOids:   5,
	}

	switch cred.Version {
	case "1":
		g.Version = gosnmp.Version1
		g.Community = cred.Community
	case "2c":
		g.Version = gosnmp.Version2c
		g.Community = cred.Community
	case "3":
		g.Version = gosnmp.Version3
		g.SecurityModel = gosnmp.UserSecurityModel
		g.MsgFlags = snmpSecurityLevel(cred.SecurityLevel)
		g.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName:                 cred.Username,
			AuthenticationProtocol:   snmpAuthProtocol(cred.AuthProtocol),
			AuthenticationPassphrase: cred.AuthPassphrase,
			PrivacyProtocol:          snmpPrivProtocol(cred.PrivProtocol),
			PrivacyPassphrase:        cred.PrivPassphrase,
		}
	default:
		return nil
	}

	if err := g.Connect(); err != nil {
		return nil
	}
	defer g.Conn.Close()

	result, err := g.Get(snmpOIDs)
	if err != nil {
		return nil
	}

	info := &SNMPInfo{}
	got := false

	for _, pdu := range result.Variables {
		oid := strings.TrimPrefix(pdu.Name, ".")
		field, ok := oidFieldMap[oid]
		if !ok {
			continue
		}

		val := pduToString(pdu)
		if val == "" {
			continue
		}

		got = true
		switch field {
		case "sysDescr":
			info.SysDescr = val
		case "sysUpTime":
			if pdu.Type == gosnmp.TimeTicks {
				ticks := gosnmp.ToBigInt(pdu.Value).Uint64()
				info.Uptime = formatSNMPUptime(ticks)
			} else {
				info.Uptime = val
			}
		case "sysContact":
			info.SysContact = val
		case "sysName":
			info.SysName = val
		case "sysLocation":
			info.SysLocation = val
		}
	}

	if !got {
		return nil
	}
	return info
}

func pduToString(pdu gosnmp.SnmpPDU) string {
	switch pdu.Type {
	case gosnmp.OctetString:
		return string(pdu.Value.([]byte))
	case gosnmp.Integer:
		return fmt.Sprintf("%d", gosnmp.ToBigInt(pdu.Value).Int64())
	case gosnmp.TimeTicks:
		return fmt.Sprintf("%d", gosnmp.ToBigInt(pdu.Value).Uint64())
	default:
		return fmt.Sprintf("%v", pdu.Value)
	}
}

func snmpSecurityLevel(level string) gosnmp.SnmpV3MsgFlags {
	switch level {
	case "authPriv":
		return gosnmp.AuthPriv
	case "authNoPriv":
		return gosnmp.AuthNoPriv
	default:
		return gosnmp.NoAuthNoPriv
	}
}

func snmpAuthProtocol(proto string) gosnmp.SnmpV3AuthProtocol {
	switch strings.ToUpper(proto) {
	case "MD5":
		return gosnmp.MD5
	case "SHA", "SHA-1":
		return gosnmp.SHA
	case "SHA-256":
		return gosnmp.SHA256
	case "SHA-512":
		return gosnmp.SHA512
	default:
		return gosnmp.NoAuth
	}
}

func snmpPrivProtocol(proto string) gosnmp.SnmpV3PrivProtocol {
	switch strings.ToUpper(proto) {
	case "DES":
		return gosnmp.DES
	case "AES", "AES-128":
		return gosnmp.AES
	case "AES-192":
		return gosnmp.AES192
	case "AES-256":
		return gosnmp.AES256
	default:
		return gosnmp.NoPriv
	}
}

// formatSNMPUptime converts TimeTicks (hundredths of seconds) to human-readable.
func formatSNMPUptime(ticks uint64) string {
	secs := ticks / 100
	days := secs / 86400
	hours := (secs % 86400) / 3600
	mins := (secs % 3600) / 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, mins)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, mins)
	}
	return fmt.Sprintf("%dm", mins)
}

// DetectSNMPPort checks if UDP 161 is potentially reachable.
func DetectSNMPPort(ip string) bool {
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:161", ip), 500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
