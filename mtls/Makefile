all: clean setup ca client server

DIR=tls

define new_cert
	# Generate private key
	openssl genrsa -out $(DIR)/keys/$1.pem 2048

    # Generate CSR
	openssl req -new -key $(DIR)/keys/$1.pem -out $(DIR)/certs/$1.csr -subj "/CN=$1"

    # Create a x509 SAN extension config to set the cert's SAN
	echo "authorityKeyIdentifier=keyid,issuer" > $(DIR)/certs/$1.ext
	echo "basicConstraints=CA:FALSE" >> $(DIR)/certs/$1.ext
	echo "keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment" >> $(DIR)/certs/$1.ext
	echo "subjectAltName = @alt_names" >> $(DIR)/certs/$1.ext
	echo "[alt_names]" >> $(DIR)/certs/$1.ext
	echo "DNS.1 = $1" >> $(DIR)/certs/$1.ext

    # Sign the certificate
	openssl x509 -req \
		-in $(DIR)/certs/$1.csr \
		-CA $(DIR)/certs/ca.pem \
		-CAkey $(DIR)/keys/ca.pem \
		-CAcreateserial \
		-out $(DIR)/certs/$1.pem \
		-days 90 \
		-sha256 \
		-extfile $(DIR)/certs/$1.ext

	rm $(DIR)/certs/$1.{csr,ext}
	rm $(DIR)/certs/ca.srl
endef

setup:
	mkdir -p $(DIR)/{certs,keys}

clean:
	rm -rf $(DIR)

# Create the CA certificate and private key
ca:
	openssl req \
		-x509 \
		-newkey rsa:2048 \
		-sha256 \
		-days 356 \
		-nodes \
		-keyout $(DIR)/keys/ca.pem \
		-out $(DIR)/certs/ca.pem \
		-subj "/CN=CA"

client:
	$(call new_cert,client)

server:
	$(call new_cert,server)
