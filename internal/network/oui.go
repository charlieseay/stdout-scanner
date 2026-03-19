package network

// ouiTable maps the first 3 bytes (OUI) of a MAC address to a vendor.
// This is a curated list of vendors commonly found in homelabs, not
// the full IEEE registry (which is ~40MB).
var ouiTable = map[string]string{
	// Apple
	"3C:22:FB": "Apple",
	"A4:83:E7": "Apple",
	"F0:18:98": "Apple",
	"AC:DE:48": "Apple",
	"14:98:77": "Apple",
	"F8:FF:C2": "Apple",
	"28:6A:BA": "Apple",
	"A8:66:7F": "Apple",

	// Raspberry Pi Foundation
	"B8:27:EB": "Raspberry Pi",
	"DC:A6:32": "Raspberry Pi",
	"E4:5F:01": "Raspberry Pi",
	"28:CD:C1": "Raspberry Pi",
	"D8:3A:DD": "Raspberry Pi",

	// Synology
	"00:11:32": "Synology",

	// QNAP
	"00:08:9B": "QNAP",
	"24:5E:BE": "QNAP",

	// Ubiquiti
	"04:18:D6": "Ubiquiti",
	"24:5A:4C": "Ubiquiti",
	"44:D9:E7": "Ubiquiti",
	"68:72:51": "Ubiquiti",
	"74:83:C2": "Ubiquiti",
	"78:8A:20": "Ubiquiti",
	"80:2A:A8": "Ubiquiti",
	"B4:FB:E4": "Ubiquiti",
	"F0:9F:C2": "Ubiquiti",
	"FC:EC:DA": "Ubiquiti",
	"E0:63:DA": "Ubiquiti",

	// TP-Link
	"50:C7:BF": "TP-Link",
	"EC:08:6B": "TP-Link",
	"14:EB:B6": "TP-Link",
	"60:32:B1": "TP-Link",
	"54:AF:97": "TP-Link",
	"98:DA:C4": "TP-Link",

	// Netgear
	"00:1B:2F": "Netgear",
	"C0:FF:D4": "Netgear",
	"28:80:88": "Netgear",
	"A4:2B:8C": "Netgear",

	// Dell
	"00:14:22": "Dell",
	"18:DB:F2": "Dell",
	"F8:DB:88": "Dell",
	"34:17:EB": "Dell",

	// HP / HPE
	"00:1A:4B": "HP",
	"3C:D9:2B": "HP",
	"94:57:A5": "HP",
	"EC:B1:D7": "HP",

	// Intel
	"00:1B:21": "Intel",
	"3C:97:0E": "Intel",
	"A4:BF:01": "Intel",
	"F8:F2:1E": "Intel",
	"48:21:0B": "Intel",

	// Cisco / Meraki
	"00:1A:A1": "Cisco",
	"00:1E:BD": "Cisco",
	"AC:17:02": "Cisco Meraki",
	"00:18:0A": "Cisco Meraki",

	// MikroTik
	"48:8F:5A": "MikroTik",
	"64:D1:54": "MikroTik",
	"00:0C:42": "MikroTik",
	"CC:2D:E0": "MikroTik",
	"6C:3B:6B": "MikroTik",

	// Supermicro
	"00:25:90": "Supermicro",
	"AC:1F:6B": "Supermicro",

	// ASUS
	"04:92:26": "ASUS",
	"1C:87:2C": "ASUS",
	"50:46:5D": "ASUS",

	// Amazon (Echo, Fire, Ring)
	"44:65:0D": "Amazon",
	"FC:65:DE": "Amazon",
	"74:C2:46": "Amazon",
	"A0:02:DC": "Amazon",
	"F0:F0:A4": "Amazon",

	// Google (Nest, Chromecast)
	"54:60:09": "Google",
	"F4:F5:D8": "Google",
	"30:FD:38": "Google",

	// Samsung
	"00:1A:8A": "Samsung",
	"BC:72:B1": "Samsung",
	"C0:97:27": "Samsung",
	"50:DC:E7": "Samsung",

	// Sonos
	"00:0E:58": "Sonos",
	"34:7E:5C": "Sonos",
	"48:A6:B8": "Sonos",
	"78:28:CA": "Sonos",

	// Espressif (ESP32, ESP8266 — common IoT)
	"24:6F:28": "Espressif",
	"30:AE:A4": "Espressif",
	"84:CC:A8": "Espressif",
	"A4:CF:12": "Espressif",
	"BC:DD:C2": "Espressif",
	"CC:50:E3": "Espressif",

	// Proxmox / common VM MACs
	"BC:24:11": "Proxmox",

	// APC (UPS)
	"00:C0:B7": "APC/Schneider",

	// CyberPower (UPS)
	"00:0B:F6": "CyberPower",

	// Brother (printers)
	"00:80:77": "Brother",

	// Canon (printers)
	"00:1E:8F": "Canon",
	"18:0C:AC": "Canon",

	// Lenovo
	"00:06:1B": "Lenovo",
	"50:7B:9D": "Lenovo",

	// Microsoft (Surface, Xbox)
	"28:18:78": "Microsoft",
	"7C:1E:52": "Microsoft",

	// VMware
	"00:0C:29": "VMware",
	"00:50:56": "VMware",

	// Docker virtual MACs
	"02:42:AC": "Docker",
}
