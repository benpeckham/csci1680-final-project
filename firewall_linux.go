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

	// 2. Send outgoing UDP/443 to NFQUEUE queue 0 so the Go QUIC inspector can
	//    inspect the first byte and only drop actual QUIC packets.
	cmdUDP := exec.Command("iptables", "-A", "OUTPUT", "-p", "udp", "--dport", "443", "-j", "NFQUEUE", "--queue-num", "0")
	if err := cmdUDP.Run(); err != nil {
		// If the second rule fails, try to clean up the first one
		cleanupFirewall()
		log.Fatalf("Failed to set UDP NFQUEUE rule: %v", err)
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

	// Remove UDP/443 NFQUEUE rule installed by setupFirewall.
	removeUntilGone("iptables", "-D", "OUTPUT",
		"-p", "udp", "--dport", "443",
		"-j", "NFQUEUE", "--queue-num", "0")
	// Also remove any legacy DROP rule in case it was left from an older run.
	removeUntilGone("iptables", "-D", "OUTPUT",
		"-p", "udp", "--dport", "443",
		"-j", "DROP")
}
