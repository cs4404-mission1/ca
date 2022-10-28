package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	caCert, err := os.ReadFile("tls/ca.crt")
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
				if len(state.PeerCertificates) > 0 && state.PeerCertificates[0].DNSNames[0] == "client" {
					return nil
				} else {
					return fmt.Errorf("invalid client certificate")
				}
			},
		},
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, world!"))
	})

	log.Printf("Starting server on %s", server.Addr)
	log.Fatal(server.ListenAndServeTLS("tls/server.crt", "tls/server.key"))
}
