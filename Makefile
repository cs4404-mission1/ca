all: clean ca exploit

clean:
	rm -f exploit/exploit ca/ca

ca:
	cd ca && CGO_LDFLAGS="-Xlinker -static" go build -o ca
	scp -i ~/.ssh/keys/wpi -P 8236 ca/ca student@secnet-gateway.cs.wpi.edu:~/
	ssh -p 8236 -i ~/.ssh/keys/wpi student@secnet-gateway.cs.wpi.edu sudo systemctl restart ca

	scp -i ~/.ssh/keys/wpi -P 8236 ca/main.go student@secnet-gateway.cs.wpi.edu:~/
	scp -i ~/.ssh/keys/wpi -P 8236 ca/crypto.go student@secnet-gateway.cs.wpi.edu:~/
	scp -i ~/.ssh/keys/wpi -P 8236 ca/challenge.go student@secnet-gateway.cs.wpi.edu:~/

exploit:
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

c-pwn:
	scp -P 8237 -i ~/.ssh/keys/wpi wfuzz.tgz student@secnet-gateway.cs.wpi.edu:~/