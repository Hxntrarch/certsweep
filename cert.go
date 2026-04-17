package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

func grabCertOrg(domain string, ports string) (string, error) {
	// Try the first port specified
	port := strings.Split(ports, ",")[0]
	addr := net.JoinHostPort(domain, port)

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return "", fmt.Errorf("TLS connect to %s: %w", addr, err)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return "", fmt.Errorf("no certificates from %s", addr)
	}

	orgs := certs[0].Subject.Organization
	if len(orgs) == 0 {
		return "", fmt.Errorf("no organization in cert from %s", addr)
	}

	return orgs[0], nil
}
