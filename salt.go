package pasap

import "crypto/rand"

// GenerateRandomSalt generates random salt
func GenerateRandomSalt(length int) []byte {
	s := make([]byte, length, length)
	_, _ = rand.Read(s)
	return s
}
