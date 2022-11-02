all: clean ca exploit

clean:
	rm -f exploit/exploit ca/ca

ca: $(shell find ca -type f)
	cd ca && CGO_LDFLAGS="-Xlinker -static" go build -o ca
	scp -i ~/.ssh/keys/wpi -P 8236 ca/ca student@secnet-gateway.cs.wpi.edu:~/

exploit: $(shell find exploit -type f)
	cd exploit && CGO_LDFLAGS="-Xlinker -static" go build -o exploit
	scp -i ~/.ssh/keys/wpi -P 8237 exploit/exploit student@secnet-gateway.cs.wpi.edu:~/

j-api:
	 ssh -p 8234 -i ~/.ssh/keys/wpi student@secnet-gateway.cs.wpi.edu
j-dns:
	 ssh -p 8235 -i ~/.ssh/keys/wpi student@secnet-gateway.cs.wpi.edu
j-ca:
	 ssh -p 8236 -i ~/.ssh/keys/wpi student@secnet-gateway.cs.wpi.edu
j-pwn:
	 ssh -p 8237 -i ~/.ssh/keys/wpi student@secnet-gateway.cs.wpi.edu
