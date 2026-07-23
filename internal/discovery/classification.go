package discovery

import "slices"

func guessMachineType(ports []uint16) string {
	hasAny := func(candidates ...uint16) bool {
		for _, port := range candidates {
			if slices.Contains(ports, port) {
				return true
			}
		}
		return false
	}

	switch {
	case hasAny(2082, 2083, 2086, 2087, 2095, 2096):
		return "cPanel/WHM server"
	case hasAny(8006):
		return "Proxmox virtualization host"
	case hasAny(3389):
		return "Windows or RDP host"
	case hasAny(3306):
		return "Database server"
	case hasAny(25, 465, 587, 110, 143, 993, 995):
		return "Mail server"
	case hasAny(53):
		return "DNS server"
	case hasAny(445):
		return "Windows or file server"
	case hasAny(80, 443, 8080, 8443):
		return "Web server"
	case hasAny(22):
		return "Linux or SSH host"
	case hasAny(21):
		return "FTP server"
	default:
		return "Unknown"
	}
}
