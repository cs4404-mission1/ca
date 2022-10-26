all: clean setup ca client server

DIR=tls

define new_cert
	# Generate private key
	openssl genrsa -out $(DIR)/$1.key 2048

    # Generate CSR
	openssl req -new -key $(DIR)/$1.key -out $(DIR)/$1.csr -subj "/CN=$1"

    # Create a x509 SAN extension config to set the cert's SAN
	echo "authorityKeyIdentifier=keyid,issuer" > $(DIR)/$1.ext
	echo "basicConstraints=CA:FALSE" >> $(DIR)/$1.ext
	echo "keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment" >> $(DIR)/$1.ext
	echo "subjectAltName = @alt_names" >> $(DIR)/$1.ext
	echo "[alt_names]" >> $(DIR)/$1.ext
	echo "DNS.1 = $1" >> $(DIR)/$1.ext

    # Sign the certificate
	openssl x509 -req \
		-in $(DIR)/$1.csr \
		-CA $(DIR)/ca.crt \
		-CAkey $(DIR)/ca.key \
		-CAcreateserial \
		-out $(DIR)/$1.crt \
		-days 90 \
		-sha256 \
		-extfile $(DIR)/$1.ext
endef

setup:
	mkdir -p $(DIR)

clean:
	rm -rf $(DIR)

# Create the CA certificate and private key
ca:
	openssl req \
		-x509 \
		-newkey rsa:4096 \
		-sha256 \
		-days 356 \
		-nodes \
		-keyout $(DIR)/ca.key \
		-out $(DIR)/ca.crt \
		-subj "/CN=CA"

client:
	$(call new_cert,client)

server:
	$(call new_cert,server)
