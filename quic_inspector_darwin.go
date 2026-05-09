//go:build darwin

package main

// startQUICInspector is a no-op on macOS. NFQUEUE is Linux-only; the macOS
// firewall (pf) continues to drop all UDP/443 traffic at the kernel level.
func startQUICInspector() {}
