

# E of Entropy

https://appliedgo.net/random/

`math/rand` vs `crypto/rand`

uniform distribution 

`math/rand` is deterministic, meaning given a known seed, the output is repeatably predictable. Not good for security!



RFC 5452 advises the use of a high quality cryptographically secure pseudo random number generator (CSPRNG) to mitigate this vulnerability.


> Proper unpredictability can be achieved by employing a high quality
> (pseudo-)random generator, as described in RFC4086. [RFC 5452 section 9.2](https://www.rfc-editor.org/rfc/rfc5452#section-9.2)

