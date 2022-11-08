package main

import (
	"fmt"
	"math/rand"
	"net"

	"github.com/miekg/dns"
)

// dnsChallenge retrieves a DNS challenge for the given domain
func dnsChallenge(domain string) (string, error) {
	var (
		local  = net.ParseIP("10.64.10.3")
		remote = net.ParseIP("10.64.10.2")
	)

	// Create DNS message
	m := new(dns.Msg)
	m.Id = uint16(rand.Intn(65535))
	m.RecursionDesired = true
	m.Question = []dns.Question{{
		Name:   dns.Fqdn("_acme-challenge." + domain),
		Qtype:  dns.TypeTXT,
		Qclass: dns.ClassINET,
	}}

	conn, err := net.DialUDP(
		"udp",
		&net.UDPAddr{IP: local, Port: 50000},
		&net.UDPAddr{IP: remote, Port: 53},
	)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	client := dns.Client{Net: "udp"}
	r, _, err := client.ExchangeWithConn(m, &dns.Conn{Conn: conn})
	if err != nil {
		return "", err
	}

	if r.Rcode != dns.RcodeSuccess {
		return "", fmt.Errorf("DNS query failed: %s", dns.RcodeToString[r.Rcode])
	}

	if len(r.Answer) == 0 {
		return "", fmt.Errorf("no answer")
	}

	if t, ok := r.Answer[0].(*dns.TXT); !ok {
		return "", fmt.Errorf("unexpected answer type: %T", r.Answer[0])
	} else {
		return t.Txt[0], nil
	}
}

// randHex generates a random 32 character hex string
func randHex() string {
	const letters = "0123456789abcdef"
	b := make([]byte, 32)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
