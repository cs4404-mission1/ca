package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"

	"github.com/miekg/dns"
)

// TODO
const openapiSpec = ""

var listen = flag.String("listen", ":8080", "Listen address")

var (
	pendingValidations = map[string]string{}

	ca     tls.Certificate
	caCert *x509.Certificate
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

// randHex generates a random hex string of the given length
func randHex(n int) string {
	const letters = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func main() {
	flag.Parse()

	http.HandleFunc("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(openapiSpec))
	})

	http.HandleFunc("/request", func(w http.ResponseWriter, r *http.Request) {
		// Retrieve domain parameter
		domain := r.URL.Query().Get("domain")
		if domain == "" {
			http.Error(w, "domain is required", http.StatusBadRequest)
			return
		}

		// Generate challenge string
		challenge := randHex(32)
		pendingValidations[domain] = challenge

		// Return challenge string to the client
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(challenge))
	})

	http.HandleFunc("/validate", func(w http.ResponseWriter, r *http.Request) {
		// Retrieve domain parameter
		domain := r.URL.Query().Get("domain")
		if domain == "" {
			http.Error(w, "domain is required", http.StatusBadRequest)
			return
		}

		// Query DNS for challenge string
		challenge, err := dnsChallenge(domain)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// Compare challenge string
		if challenge != pendingValidations[domain] {
			http.Error(w, "challenge mismatch", http.StatusUnauthorized)
			return
		}

		// Cleanup challenge
		delete(pendingValidations, domain)

		// Generate certificate for domain
		certPEM, keyPEM, err := newCert(domain, caCert, ca.PrivateKey.(*rsa.PrivateKey))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Return certificate to the client
		w.Header().Set("Content-Type", "text/plain")
		w.Write(certPEM)
		w.Write([]byte(";"))
		w.Write(keyPEM)
	})

	http.HandleFunc("/challenge", func(w http.ResponseWriter, r *http.Request) {
		// Retrieve domain parameter
		domain := r.URL.Query().Get("domain")
		if domain == "" {
			http.Error(w, "domain is required", http.StatusBadRequest)
			return
		}

		// Query DNS for challenge string
		challenge, err := dnsChallenge(domain)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		// Return challenge to user
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(challenge))
	})

	http.HandleFunc("/cert", func(w http.ResponseWriter, r *http.Request) {
		filename := r.URL.Query().Get("name")
		content, err := os.ReadFile("mtls/tls/certs/" + filename + ".pem")
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}

		// Parse x509 certificate
		block, rest := pem.Decode(content)
		log.Printf("block: %v, rest: %v", block, rest)

		w.Header().Set("Content-Type", "text/plain")
		w.Write(content)
	})

	// Check if CA key exists
	if _, err := os.Stat("ca-key.pem"); os.IsNotExist(err) {
		log.Println("Generating new CA")
		if err := newCA(); err != nil {
			log.Fatal(err)
		}
	}

	// Import the CA cert and key to memory
	log.Print("Importing CA")
	var err error
	ca, err = tls.LoadX509KeyPair("ca-crt.pem", "ca-key.pem")
	if err != nil {
		log.Fatal(err)
	}

	// Parse the CA cert
	caCert, err = x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Starting CA server on %s", *listen)
	log.Fatal(http.ListenAndServe(*listen, nil))
}
