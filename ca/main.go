package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"os"

	"github.com/gofiber/fiber/v2"
)

var (
	listen = flag.String("listen", ":443", "Listen address")
	genCA  = flag.Bool("gen-ca", false, "Generate a new CA")
)

var (
	pendingValidations = map[string]string{}

	ca     tls.Certificate
	caCert *x509.Certificate
)

func main() {
	flag.Parse()

	app := fiber.New()

	// Set server header
	app.Use(func(c *fiber.Ctx) error {
		c.Set("Server", "digishue-go")
		return c.Next()
	})

	app.Post("/request", func(c *fiber.Ctx) error {
		// Retrieve domain parameter
		domain := c.Query("domain")
		if domain == "" {
			return c.Status(400).SendString("missing domain parameter")
		}

		// Generate challenge string
		challenge := randHex()
		pendingValidations[domain] = challenge

		// Return challenge string to the client
		return c.SendString(challenge)
	})

	app.Get("/challenge", func(c *fiber.Ctx) error {
		// Retrieve domain parameter
		domain := c.Query("domain")
		if domain == "" {
			return c.Status(400).SendString("missing domain parameter")
		}

		// Query DNS for challenge string
		challenge, err := dnsChallenge(domain)
		if err != nil {
			return c.Status(500).SendString(err.Error())
		}

		// Return challenge string to the client
		return c.SendString(challenge)
	})

	app.Post("/validate", func(c *fiber.Ctx) error {
		// Retrieve domain parameter
		domain := c.Query("domain")
		if domain == "" {
			return c.Status(400).SendString("missing domain parameter")
		}

		// Query DNS for challenge string
		challenge, err := dnsChallenge(domain)
		if err != nil {
			return c.Status(500).SendString(err.Error())
		}

		// Compare challenge string
		if challenge != pendingValidations[domain] {
			return c.Status(400).SendString("invalid challenge")
		}

		// Cleanup challenge
		delete(pendingValidations, domain)

		// Generate certificate for domain
		certPEM, keyPEM, err := newCert([]string{domain}, caCert, ca.PrivateKey.(*rsa.PrivateKey))
		if err != nil {
			return c.Status(500).SendString(err.Error())
		}

		// Return certificate to the client
		return c.SendString(string(certPEM) + ";" + string(keyPEM))
	})

	app.Get("/static", func(c *fiber.Ctx) error {
		// Get url path
		path := c.Query("path")
		if path == "" {
			return c.SendString(`openapi: 3.0.1
info:
  title: DigiShue Certificate Authority
  version: 1.0.0
servers:
- url: https://ca.internal
paths:
  /request:
    post:
      summary: Request a certificate for a given domain
      parameters:
        - in: query
          name: domain
          required: true
          schema:
            type: string
          description: The domain to request a certificate for
      responses:
        '200':
          description: TXT challenge string

  /validate:
    post:
      summary: Validate a domain's DNS challenge and issue a certificate 
      parameters:
        - in: query
          name: domain
          required: true
          schema:
            type: string
          description: Domain to validate
      responses:
        '200':
          description: PEM encoded certificate and private key

  /static:
    post:
      summary: Retrieve a static asset
      parameters:
        - in: query
          name: path
          schema:
            type: string
          description: Static asset to retrieve
      responses:
        '200':
          description: Static asset
`)
		}

		content, err := os.ReadFile("static/" + path)
		if err != nil {
			return c.Status(500).SendString(err.Error())
		}

		return c.SendString(string(content))
	})

	// Make static directory if it doesn't exist
	if _, err := os.Stat("static"); os.IsNotExist(err) {
		if err := os.Mkdir("static", 0755); err != nil {
			log.Fatal(err)
		}
	}

	// Check if CA key exists
	if _, err := os.Stat("ca-key.pem"); os.IsNotExist(err) || *genCA {
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
	log.Fatal(app.ListenTLS(*listen, "ca-web-crt.pem", "ca-web-key.pem"))
}
