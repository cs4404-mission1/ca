# CS4404 Mission 1

- Compromise CA by requesting a cert for the attacker's machine, correctly validating the ACME challenge to get a cert for the attacker. Use it to authenticate with mTLS.
- Now we can use the client's private key to authenticate to the tabulator API
- Watch the tabulator API and wait until it's a "good" time to invalidate the cached tokens
- Crash the database or API to invalidate cached access tokens in API memory and/or ephemeral vote data

## Mitigations

Defense in depth:

- Protect the CA network with a firewall (or any routed network segment)
- Protect admin API with a firewall
- Fix crash bug
