package main

import (
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// simulates broken pipe when written to
type readOnlyConn struct {
	reader io.Reader
}

func (conn readOnlyConn) Read(p []byte) (int, error)         { return conn.reader.Read(p) }
func (conn readOnlyConn) Write(p []byte) (int, error)        { return 0, io.ErrClosedPipe }
func (conn readOnlyConn) Close() error                       { return nil }
func (conn readOnlyConn) LocalAddr() net.Addr                { return nil }
func (conn readOnlyConn) RemoteAddr() net.Addr               { return nil }
func (conn readOnlyConn) SetDeadline(t time.Time) error      { return nil }
func (conn readOnlyConn) SetReadDeadline(t time.Time) error  { return nil }
func (conn readOnlyConn) SetWriteDeadline(t time.Time) error { return nil }

func main() {
	// ensure program is run as root
	if os.Geteuid() != 0 {
		log.Fatalf("This program must be run as root (sudo) to configure the firewall.")
	}

	// apply firewall rules
	// firewall tells the OS to redirect all traffic to the proxy server
	setupFirewall()
	defer cleanupFirewall()

	// AI generated code to ensure safe shutdown
	// ---------------------------------------------
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	// ---------------------------------------------

	// start proxy server in goroutine
	go startProxyServer("127.0.0.1:8080")

	// start QUIC inspector: reads UDP/443 packets from NFQUEUE and drops only QUIC
	go startQUICInspector()

	// ---------------------------------------------
	<-sigChan
	// ---------------------------------------------

}

func startProxyServer(listenAddr string) {
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
		go handleConnection(conn)
	}
}

// hardcoded domains for now
func isBlocked(domain string) bool {

	if strings.Contains(strings.ToLower(domain), "youtube.com") {
		return true
	}
	if strings.Contains(strings.ToLower(domain), "googlevideo.com") {
		return true
	}
	return false
}

/*
Problem: if you read a byte from a TCP socket, it is deleted from the socket's buffer
Solution:
  - browser sends client hello to our proxy
  - we wrap the connection in a readOnlyConn that simulates a broken pipe when written to
  - we simultaneously read the client hello and store the domain name
  - we can now check the domain name and block the connection if necessary
  - if domain is allowed, we prepend the client hello to the socket's buffer
  - we can now route the connection to the destination server
*/
func handleConnection(conn net.Conn) {
	defer conn.Close()

	// peek the client hello
	clientHello, stitchedReader, err := peekClientHello(conn)
	if err != nil {
		log.Printf("Failed to peek TLS: %v", err)
		return
	}

	// extract the domain name
	domain := clientHello.ServerName
	if domain == "" {
		log.Println("No domain found in ClientHello, dropping connection.")
		return
	}

	// consult blocklist
	if isBlocked(domain) {
		log.Printf("[BLOCKED] Dropping connection to %s", domain)
		return
	}

	log.Printf("[ALLOWED]: Forwarding connection to %s", domain)

	// open our own TCP connection to the destination server
	targetAddr := domain + ":443"
	destConn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		log.Printf("Failed to connect to %s: %v", targetAddr, err)
		return
	}

	defer destConn.Close()

	done := make(chan struct{}, 2)

	// constantly route all incoming bytes from the server to the browser
	go func() {
		io.Copy(conn, destConn)
		done <- struct{}{}
	}()

	// constantly route all incoming bytes from the browser to the server
	// stiched reader also routes bytes from the proxy to the server
	go func() {
		io.Copy(destConn, stitchedReader)
		done <- struct{}{}
	}()

	<-done

}

func readClientHello(reader io.Reader) (*tls.ClientHelloInfo, error) {
	var hello *tls.ClientHelloInfo

	err := tls.Server(readOnlyConn{reader: reader}, &tls.Config{
		GetConfigForClient: func(argHello *tls.ClientHelloInfo) (*tls.Config, error) {
			hello = new(tls.ClientHelloInfo)
			*hello = *argHello
			return nil, nil
		},
	}).Handshake()

	if hello == nil {
		return nil, err
	}

	return hello, nil
}

func peekClientHello(reader io.Reader) (*tls.ClientHelloInfo, io.Reader, error) {
	peekedBytes := new(bytes.Buffer)

	// reader that also writes what is read to our buffer
	hello, err := readClientHello(io.TeeReader(reader, peekedBytes))
	if err != nil {
		return nil, nil, err
	}

	// reader that reads from our buffer first, then the original reader
	return hello, io.MultiReader(peekedBytes, reader), nil
}
