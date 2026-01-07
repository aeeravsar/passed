package password

// 16 characters, alphanumeric, capitals included
const (
	PasswordLength = 16
	Charset        = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

// Generate converts derived bytes to alphanumeric password
// Uses rejection sampling to avoid modulo bias
func Generate(derived []byte) string {
	if len(derived) < 64 {
		panic("derived key must be at least 64 bytes")
	}

	password := make([]byte, PasswordLength)
	charsetLen := uint16(len(Charset))

	// Calculate the largest multiple of charsetLen that fits in uint16
	// Use uint32 to avoid overflow, then convert result
	const maxUint16 = 65536
	maxValid := uint16((maxUint16 / uint32(charsetLen)) * uint32(charsetLen))

	byteIdx := 0
	for i := 0; i < PasswordLength; i++ {
		// Keep trying until we get a value without bias
		for {
			// Safety check: ensure we don't exceed derived bytes
			if byteIdx+1 >= len(derived) {
				panic("ran out of random bytes during password generation")
			}

			// Construct a 16-bit value from two bytes
			idx := (uint16(derived[byteIdx]) << 8) | uint16(derived[byteIdx+1])
			byteIdx += 2

			// Reject values that would cause bias
			if idx < maxValid {
				password[i] = Charset[idx%charsetLen]
				break
			}
			// If rejected, loop will try next two bytes
		}
	}

	return string(password)
}
