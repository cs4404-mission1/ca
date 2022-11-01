package main

import (
	"flag"
	"log"
	"math/rand"
	"net"

	"github.com/miekg/dns"
)

var (
	local  = flag.String("l", "10.64.10.3", "local IP address")
	remote = flag.String("r", "10.64.10.2", "DNS server")
)

func main() {
	flag.Parse()

	// Create DNS message
	m := new(dns.Msg)
	m.Id = uint16(rand.Intn(65535))
	m.RecursionDesired = true
	m.Question = []dns.Question{{
		Name:   "_acme-challenge.admin.shueworld.internal.",
		Qtype:  dns.TypeTXT,
		Qclass: dns.ClassINET,
	}}

	conn, err := net.DialUDP(
		"udp",
		&net.UDPAddr{IP: net.ParseIP(*local), Port: 50000},
		&net.UDPAddr{IP: net.ParseIP(*remote), Port: 53},
	)
	if err != nil {
		log.Fatalf("Failed to dial: %v", err)
	}
	defer conn.Close()

	client := dns.Client{Net: "udp"}
	r, _, err := client.ExchangeWithConn(m, &dns.Conn{Conn: conn})
	if err != nil {
		log.Fatalf("DNS exchange: %s", err)
	}

	log.Printf("Status: %d, ID: %d", r.MsgHdr.Rcode, r.Id)
	for _, a := range r.Answer {
		if t, ok := a.(*dns.TXT); ok {
			log.Println(t.Txt)
		}
	}
}
