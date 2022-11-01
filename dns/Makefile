all: clean deploy-dns deploy-exploit

clean:
	rm -rf dns exploit

dns: dns.go
	CGO_LDFLAGS="-Xlinker -static" go build -o dns dns.go

deploy-dns: dns
	scp -i ~/.ssh/keys/wpi -P 8236 dns student@secnet-gateway.cs.wpi.edu:~/

exploit: exploit.go
	CGO_LDFLAGS="-Xlinker -static" go build -o exploit exploit.go

deploy-exploit: exploit
	scp -i ~/.ssh/keys/wpi -P 8237 exploit student@secnet-gateway.cs.wpi.edu:~/
