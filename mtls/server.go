package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
)

var (
	caCertFile          = flag.String("ca-cert", "tls/certs/ca.pem", "CA certificate")
	serverCertFile      = flag.String("server-cert", "tls/certs/server.pem", "Server certificate")
	serverKeyFile       = flag.String("server-key", "tls/keys/server.pem", "Server key")
	authorizedClientSAN = flag.String("authorized-san", "client", "Authorized client SAN")
)

func main() {
	flag.Parse()

	caCert, err := os.ReadFile(*caCertFile)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	server := &http.Server{
		Addr: ":8443",
		TLSConfig: &tls.Config{
			ClientCAs:  caCertPool,
			ClientAuth: tls.RequireAndVerifyClientCert,
			VerifyConnection: func(state tls.ConnectionState) error {
				if len(state.PeerCertificates) > 0 && state.PeerCertificates[0].DNSNames[0] == *authorizedClientSAN {
					return nil
				} else {
					return fmt.Errorf("invalid client certificate")
				}
			},
		},
	}

	http.HandleFunc("/key", func(w http.ResponseWriter, r *http.Request) {
		// Generate random 256bit key
		key := make([]byte, 32)
		_, err := rand.Read(key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.Write([]byte(fmt.Sprintf("%x", key)))
	})

	log.Printf("Starting server on %s", server.Addr)
	log.Fatal(server.ListenAndServeTLS(*serverCertFile, *serverKeyFile))
}
