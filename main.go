package csci1680finalproject

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// ensure program is run as root
	if os.Geteuid() != 0 {
		log.Fatalf("This program must be run as root (sudo) to configure the firewall.")
	}

	// apply firewall rules
	// firewall tells the OS to redirect all traffic to the proxy server
	setupFirewall()

	// AI generated code to ensure safe shutdown
	// ---------------------------------------------
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	// ---------------------------------------------

	// load blocked domains
	blockedDomains := getBlockedDomains()

	// start proxy server in goroutine
	go startProxyServer("127.0.0.1:8080", blockedDomains)

	// ---------------------------------------------
	<-sigChan
	cleanupFirewall()
	// ---------------------------------------------

}

func startProxyServer(listenAddr string, blockedDomains map[string]bool) {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("Failed to start listener: %v", err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Error accepting connection: %v", err)
			continue
		}

		// handle connection asynchronously
		go handleConnection(conn, blockedDomains)
	}
}

// hardcoded list of domains to block
// using a map for O(1) lookup
func getBlockedDomains() map[string]bool {
	return map[string]bool{
		"youtube.com":     true,
		"www.youtube.com": true,
		"m.youtube.com":   true,
		"youtu.be":        true,
	}
}

func handleConnection(conn net.Conn, blockedDomains map[string]bool) {
	defer conn.Close()

	// TODO: figure out SNI peaking
	// resource: https://www.agwa.name/blog/post/writing_an_sni_proxy_in_go

}
