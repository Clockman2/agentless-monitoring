package discovery

import "testing"

func TestGuessMachineType(t *testing.T) {
	tests := []struct {
		name  string
		ports []uint16
		want  string
	}{
		{name: "cPanel takes precedence", ports: []uint16{22, 80, 443, 2083, 3306}, want: "cPanel/WHM server"},
		{name: "cPanel DNSOnly secure WHM", ports: []uint16{22, 53, 953, 2087}, want: "cPanel DNSOnly server"},
		{name: "cPanel DNSOnly WHM", ports: []uint16{22, 53, 2086}, want: "cPanel DNSOnly server"},
		{name: "cPanel with user interface is not DNSOnly", ports: []uint16{53, 2083, 2087}, want: "cPanel/WHM server"},
		{name: "Proxmox", ports: []uint16{22, 8006}, want: "Proxmox virtualization host"},
		{name: "Windows remote desktop", ports: []uint16{80, 3389}, want: "Windows or RDP host"},
		{name: "mail", ports: []uint16{80, 993}, want: "Mail server"},
		{name: "web", ports: []uint16{22, 443}, want: "Web server"},
		{name: "SSH", ports: []uint16{22}, want: "Linux or SSH host"},
		{name: "unknown", ports: nil, want: "Unknown"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := guessMachineType(test.ports); got != test.want {
				t.Fatalf("guessMachineType(%v) = %q, want %q", test.ports, got, test.want)
			}
		})
	}
}
