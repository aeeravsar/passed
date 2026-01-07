package crypto

import (
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	Argon2MemoryKB    = 256 * 1024 // 256 MB in KB
	Argon2TimeCost    = 4
	Argon2Parallelism = 2
	Argon2HashLen     = 64
	Argon2SaltPrefix  = "passed"
)

// DeriveKey derives a 64-byte key using Argon2id
// The mnemonic phrase is the secret input, while domain and counter are included in the salt
// This ensures each domain/counter combination has a unique salt, preventing rainbow table attacks
func DeriveKey(phrase, domain string, counter int) []byte {
	phrase = strings.ToLower(strings.TrimSpace(phrase))
	domain = strings.ToLower(strings.TrimSpace(domain))

	// Construct a unique salt from the domain and counter
	salt := fmt.Sprintf("%s|%s|%d", Argon2SaltPrefix, domain, counter)

	derived := argon2.IDKey(
		[]byte(phrase),     // secret
		[]byte(salt),       // unique salt per domain/counter
		Argon2TimeCost,     // time
		Argon2MemoryKB,     // memory in KB
		Argon2Parallelism,  // threads
		Argon2HashLen,      // key length
	)

	return derived
}
