package pasap

import (
	"crypto/rand"
	"io"
)

// GetSalt receives salt from the reader
func GetSalt(length int, reader io.Reader) []byte {
	if reader == nil {
		reader = rand.Reader
	}
	s := make([]byte, length, length)
	_, err := io.ReadFull(reader, s)

	if err != nil {
		return nil
	}
	return s
}
