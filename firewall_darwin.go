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

	// Rule 1: Redirect TCP 443 to our proxy.
	// Rule 2: Block UDP 443 entirely to drop QUIC connections.
	// Note: macOS pf does not support user/UID filtering inside rdr rules.
	rules := `
		rdr pass on en0 inet proto tcp from any to any port 443 -> 127.0.0.1 port 8080
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
