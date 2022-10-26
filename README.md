# CS4404 Mission 1

- Compromise CA
  - Pop the apt repo with a backdoored openssl package with predictable entropy
  - or...
  - Exploit CA's ACME interface to request a new cert for the client
- Now we can use the client's private key to authenticate to the tabulator API
- Watch the tabulator API and wait until it's a "good" time to invalidate the cached tokens
- Crash the database or API to invalidate cached access tokens in API memory and/or ephemeral vote data
