package csci1680finalproject

import (
	"log"
	"os/exec"
)

// This version of setupFirewall only compiles on Linux
// AI generated code to configure the iptables firewall on Linux
func setupFirewall() {
	log.Println("Configuring Linux iptables...")

	// 1. Redirect TCP 443 to our local port 8080
	cmdTCP := exec.Command("iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-ports", "8080")
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
	// Remove the iptables rule
	exec.Command("iptables", "-t", "nat", "-D", "OUTPUT", "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-ports", "8080").Run()
}
