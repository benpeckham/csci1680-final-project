package main

import (
	"bytes"
	"log"
	"os/exec"
)

// This version of setupFirewall only compiles on macOS
// AI generated code to configure the pf firewall on macOS
func setupFirewall() {
	log.Println("Configuring macOS pf firewall...")

	// macOS pf cannot filter by user inside rdr rules, so we use a two-rule approach:
	// Rule 1: Reroute non-root outbound TCP/443 to lo0 (browsers run as non-root).
	//         user != root prevents the proxy's own outbound TLS from looping back to 8080.
	// Rule 2: Intercept traffic arriving on lo0 port 443 and forward to proxy on 8080.
	// Rule 3: Block UDP/443 to prevent QUIC, forcing browsers onto TCP TLS.
	rules := `
rdr pass on lo0 inet proto tcp from any to any port 443 -> 127.0.0.1 port 8080
pass out route-to lo0 inet proto tcp from any to any port 443 user != root
block drop out proto udp to any port 443
`
	cmd := exec.Command("pfctl", "-E", "-f", "-")
	cmd.Stdin = bytes.NewBufferString(rules)

	if err := cmd.Run(); err != nil {
		log.Fatalf("Failed to set pf firewall rule: %v", err)
	}
}

func cleanupFirewall() {
	exec.Command("pfctl", "-F", "all", "-d").Run()
}
