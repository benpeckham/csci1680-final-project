package main

import (
	"log"
	"os/exec"
)

// This version of setupFirewall only compiles on Linux
// AI generated code to configure the iptables firewall on Linux
func setupFirewall() {
	log.Println("Configuring Linux iptables...")

	// 1. Redirect TCP 443 to our local port 8080 (non-root only).
	// Without this, the proxy's own outbound TLS (running as root) would be redirected back to 8080.
	cmdTCP := exec.Command("iptables", "-t", "nat", "-A", "OUTPUT",
		"-p", "tcp", "--dport", "443",
		"-m", "owner", "!", "--uid-owner", "0",
		"-j", "REDIRECT", "--to-ports", "8080")
	if err := cmdTCP.Run(); err != nil {
		log.Fatalf("Failed to set TCP intercept rule: %v", err)
	}

	// 2. Drop all outgoing UDP traffic on port 443 to drop QUIC connections
	cmdUDP := exec.Command("iptables", "-A", "OUTPUT", "-p", "udp", "--dport", "443", "-j", "DROP")
	if err := cmdUDP.Run(); err != nil {
		// If the second rule fails, try to clean up the first one
		cleanupFirewall()
		log.Fatalf("Failed to set UDP drop rule: %v", err)
	}
}

func cleanupFirewall() {
	log.Println("Removing Linux iptables rules...")

	// NAT redirect (current rule with owner match). Repeat -D until none left (duplicate rules).
	removeUntilGone := func(args ...string) {
		for {
			cmd := exec.Command(args[0], args[1:]...)
			if err := cmd.Run(); err != nil {
				break
			}
		}
	}
	removeUntilGone("iptables", "-t", "nat", "-D", "OUTPUT",
		"-p", "tcp", "--dport", "443",
		"-m", "owner", "!", "--uid-owner", "0",
		"-j", "REDIRECT", "--to-ports", "8080")
	// Older installs without owner match — same symptom (HTTPS stuck to dead proxy).
	removeUntilGone("iptables", "-t", "nat", "-D", "OUTPUT",
		"-p", "tcp", "--dport", "443",
		"-j", "REDIRECT", "--to-ports", "8080")

	// UDP/443 DROP from setupFirewall was never removed before; leftover breaks QUIC / some stacks.
	removeUntilGone("iptables", "-D", "OUTPUT",
		"-p", "udp", "--dport", "443",
		"-j", "DROP")
}
