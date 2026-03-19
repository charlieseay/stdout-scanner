package network

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// SNMP OIDs for system MIB-2 (RFC 1213) — these are universal across
// all SNMP-capable devices.
var snmpOIDs = map[string]string{
	"1.3.6.1.2.1.1.1.0": "sysDescr",
	"1.3.6.1.2.1.1.3.0": "sysUpTime",
	"1.3.6.1.2.1.1.4.0": "sysContact",
	"1.3.6.1.2.1.1.5.0": "sysName",
	"1.3.6.1.2.1.1.6.0": "sysLocation",
}

// querySNMP attempts an SNMPv2c GET on the standard system OIDs.
// Uses the "public" community string (read-only, default on most devices).
// Returns nil if the device doesn't respond to SNMP.
//
// We implement a minimal SNMPv2c GET ourselves rather than importing
// a full SNMP library — keeps the binary small and dependency-free.
func querySNMP(ctx context.Context, ip string) *SNMPInfo {
	addr := fmt.Sprintf("%s:161", ip)

	// Quick check: is UDP 161 reachable? Send a valid GetRequest.
	info := &SNMPInfo{}
	got := false

	for oid, field := range snmpOIDs {
		val := snmpGet(ctx, addr, "public", oid)
		if val == "" {
			continue
		}
		got = true
		switch field {
		case "sysDescr":
			info.SysDescr = val
		case "sysUpTime":
			info.Uptime = formatSNMPUptime(val)
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

	fmt.Fprintf(os.Stderr, "    SNMP %s: %s (%s)\n", ip, info.SysName, info.SysDescr)
	return info
}

// snmpGet performs a single SNMPv2c GetRequest for one OID.
// Returns the string value or empty string on failure.
func snmpGet(ctx context.Context, addr, community, oid string) string {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(2 * time.Second)
	}

	conn, err := net.DialTimeout("udp", addr, 1*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(deadline)

	// Build SNMPv2c GetRequest packet
	pkt := buildGetRequest(community, oid)
	if _, err := conn.Write(pkt); err != nil {
		return ""
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return ""
	}

	return parseGetResponse(buf[:n])
}

// buildGetRequest constructs a minimal SNMPv2c GetRequest PDU.
func buildGetRequest(community, oid string) []byte {
	// Encode OID
	oidBytes := encodeOID(oid)

	// VarBind: SEQUENCE { OID, NULL }
	varbind := asn1Sequence(append(oidBytes, 0x05, 0x00)) // OID + NULL

	// VarBindList: SEQUENCE { varbind }
	varbindList := asn1Sequence(varbind)

	// PDU: GetRequest [0] { request-id, error-status, error-index, varbindlist }
	requestID := []byte{0x02, 0x01, 0x01}       // INTEGER 1
	errorStatus := []byte{0x02, 0x01, 0x00}     // INTEGER 0
	errorIndex := []byte{0x02, 0x01, 0x00}      // INTEGER 0

	pduContent := append(requestID, errorStatus...)
	pduContent = append(pduContent, errorIndex...)
	pduContent = append(pduContent, varbindList...)

	// GetRequest-PDU [0] IMPLICIT
	pdu := asn1Constructed(0xa0, pduContent)

	// Message: SEQUENCE { version, community, pdu }
	version := []byte{0x02, 0x01, 0x01} // INTEGER 1 (SNMPv2c)
	communityBytes := asn1OctetString([]byte(community))

	msgContent := append(version, communityBytes...)
	msgContent = append(msgContent, pdu...)

	return asn1Sequence(msgContent)
}

// parseGetResponse extracts the value from an SNMP GetResponse.
func parseGetResponse(data []byte) string {
	// We need to navigate: SEQUENCE > skip version+community > PDU > skip ids > VarBindList > VarBind > value
	// This is a minimal parser — we look for the value after the OID in the response.

	// Find the last varbind value. Walk through looking for OctetString or Integer values
	// after position ~30 (past headers).
	if len(data) < 20 {
		return ""
	}

	// Simple approach: scan for value types in the tail of the response
	// The response structure is well-defined, so find the VarBind value.
	pos := 0

	// Skip outer SEQUENCE
	pos, _ = skipTLV(data, pos)
	if pos < 0 {
		return ""
	}

	// We're inside the outer sequence. Walk through TLVs.
	// version (INTEGER), community (OCTET STRING), PDU (CONTEXT[2])
	// Inside PDU: request-id, error-status, error-index, varbindlist
	// Inside varbindlist: varbind (SEQUENCE of OID + value)

	// Rather than full ASN.1 parsing, find the value at the end.
	// The last TLV in the packet is the value we want.
	return extractLastValue(data)
}

// extractLastValue finds the last OctetString, Integer, or TimeTicks value
// in an SNMP response. Works because the response is a flat-ish structure
// and the value is always last.
func extractLastValue(data []byte) string {
	// Walk through the data looking for value TLVs
	i := 0
	lastVal := ""

	for i < len(data)-2 {
		tag := data[i]
		length, lenSize := decodeLength(data[i+1:])
		if length < 0 || lenSize < 0 {
			i++
			continue
		}

		start := i + 1 + lenSize
		end := start + length

		if end > len(data) {
			i++
			continue
		}

		switch tag {
		case 0x04: // OCTET STRING
			lastVal = string(data[start:end])
		case 0x02: // INTEGER
			if length <= 4 {
				val := 0
				for _, b := range data[start:end] {
					val = val<<8 | int(b)
				}
				lastVal = fmt.Sprintf("%d", val)
			}
		case 0x43: // TimeTicks
			if length <= 4 {
				val := uint32(0)
				for _, b := range data[start:end] {
					val = val<<8 | uint32(b)
				}
				// TimeTicks is in hundredths of a second
				lastVal = fmt.Sprintf("%d", val)
			}
		case 0x30, 0xa2, 0xa0: // SEQUENCE, GetResponse, GetRequest — recurse into
			i++
			continue
		}

		i = end
	}

	return lastVal
}

func decodeLength(data []byte) (int, int) {
	if len(data) == 0 {
		return -1, -1
	}
	if data[0] < 0x80 {
		return int(data[0]), 1
	}
	numBytes := int(data[0] & 0x7f)
	if numBytes == 0 || numBytes > 4 || len(data) < numBytes+1 {
		return -1, -1
	}
	length := 0
	for i := 1; i <= numBytes; i++ {
		length = length<<8 | int(data[i])
	}
	return length, numBytes + 1
}

func skipTLV(data []byte, pos int) (int, int) {
	if pos >= len(data) {
		return -1, -1
	}
	if pos+1 >= len(data) {
		return -1, -1
	}
	length, lenSize := decodeLength(data[pos+1:])
	if length < 0 {
		return -1, -1
	}
	// Return content start position and content end
	contentStart := pos + 1 + lenSize
	return contentStart, contentStart + length
}

// encodeOID encodes a dotted OID string as ASN.1 OID bytes with tag.
func encodeOID(oid string) []byte {
	parts := strings.Split(oid, ".")
	if len(parts) < 2 {
		return nil
	}

	var nums []int
	for _, p := range parts {
		n := 0
		for _, c := range p {
			n = n*10 + int(c-'0')
		}
		nums = append(nums, n)
	}

	// First two components encoded as 40*X + Y
	encoded := []byte{byte(40*nums[0] + nums[1])}

	for _, n := range nums[2:] {
		encoded = append(encoded, encodeSubOID(n)...)
	}

	// Tag 0x06 (OID) + length + content
	result := []byte{0x06, byte(len(encoded))}
	return append(result, encoded...)
}

func encodeSubOID(val int) []byte {
	if val < 128 {
		return []byte{byte(val)}
	}
	var parts []byte
	parts = append(parts, byte(val&0x7f))
	val >>= 7
	for val > 0 {
		parts = append(parts, byte(val&0x7f|0x80))
		val >>= 7
	}
	// Reverse
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return parts
}

func asn1Sequence(content []byte) []byte {
	return asn1Constructed(0x30, content)
}

func asn1Constructed(tag byte, content []byte) []byte {
	return append([]byte{tag, byte(len(content))}, content...)
}

func asn1OctetString(val []byte) []byte {
	return append([]byte{0x04, byte(len(val))}, val...)
}

// formatSNMPUptime converts TimeTicks (hundredths of seconds) to human-readable.
func formatSNMPUptime(ticks string) string {
	val := 0
	for _, c := range ticks {
		if c >= '0' && c <= '9' {
			val = val*10 + int(c-'0')
		}
	}
	secs := val / 100
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
