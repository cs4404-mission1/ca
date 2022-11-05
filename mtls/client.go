package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
)

var (
	rocketConfig   = flag.String("rocket-config", "Rocket.toml", "Rocket config file")
	caCertFile     = flag.String("ca-cert", "tls/certs/ca.pem", "CA certificate")
	clientCertFile = flag.String("client-cert", "tls/certs/client.pem", "Client certificate")
	clientKeyFile  = flag.String("client-key", "tls/keys/client.pem", "Client key")
	url            = flag.String("url", "https://server:8443/key", "URL to fetch secret key from")
)

func replaceSecret(secret string) error {
	// Read config file
	f, err := os.ReadFile(*rocketConfig)
	if err != nil {
		return err
	}

	// Replace secret
	re := regexp.MustCompile(`secret_key = ".*"`)
	f = re.ReplaceAll(f, []byte(`secret_key = "`+secret+`"`))

	// Write config file
	return os.WriteFile(*rocketConfig, f, 0644)
}

func main() {
	flag.Parse()

	caCert, err := os.ReadFile(*caCertFile)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	cert, err := tls.LoadX509KeyPair(*clientCertFile, *clientKeyFile)
	if err != nil {
		log.Fatal(err)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      caCertPool,
				Certificates: []tls.Certificate{cert},
			},
		},
	}

	r, err := client.Get(*url)
	if err != nil {
		log.Fatal(err)
	}
	defer r.Body.Close()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Replacing secret key with %s", body)
	if err := replaceSecret(string(body)); err != nil {
		log.Fatal(err)
	}
}
