package pasap

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/argon2"
	"strings"
)

// Argon2idHasher uses argon2id password hashing algorithm
// to generate secret key and verify encoded key
type Argon2idHasher struct {
	// Defines the amount of computation time, given in number of iterations.
	Time uint32
	// Defines the memory usage (KiB).
	Memory uint32
	// Defines the number of parallel threads.
	Threads uint8
	// Defines the length of the hash in bytes.
	Length uint32
}

func (a *Argon2idHasher) Name() string {
	return "argon2id"
}

func (a *Argon2idHasher) Encode(password, salt []byte) (secretKey, encodedKey []byte) {
	secretKey = argon2.IDKey(password, salt, a.Time, a.Memory, a.Threads, a.Length)
	hash := argon2.IDKey(secretKey, salt, a.Time, a.Memory, a.Threads, a.Length)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	s := fmt.Sprintf("%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		a.Name(),
		argon2.Version,
		a.Memory,
		a.Time,
		a.Threads,
		b64Salt,
		b64Hash,
	)
	encodedKey = []byte(s)
	return secretKey, encodedKey
}

func (a *Argon2idHasher) Verify(password, encodedKey []byte) (bool, error) {
	s := strings.Split(string(encodedKey), "$")

	if len(s) != 5 {
		return false, ErrHashComponentMismatch
	}

	algorithm, version, params, salt, hash := s[0], s[1], s[2], s[3], s[4]

	if algorithm != a.Name() {
		return false, ErrAlgorithmMismatch
	}

	var v int
	var err error

	_, err = fmt.Sscanf(version, "v=%d", &v)

	if err != nil {
		return false, ErrHashComponentUnreadable
	}

	if v != argon2.Version {
		return false, ErrIncompatibleVersion
	}

	var time, memory uint32
	var threads uint8

	_, err = fmt.Sscanf(string(params), "m=%d,t=%d,p=%d", &memory, &time, &threads)

	if err != nil {
		return false, ErrHashComponentUnreadable
	}

	bSalt, err := base64.RawStdEncoding.DecodeString(salt)

	if err != nil {
		return false, ErrHashComponentUnreadable
	}

	bHash, err := base64.RawStdEncoding.DecodeString(hash)

	if err != nil {
		return false, ErrHashComponentUnreadable
	}

	secretKey := argon2.IDKey(password, bSalt, time, memory, threads, uint32(len(bHash)))
	newHash := argon2.IDKey(secretKey, bSalt, time, memory, threads, uint32(len(bHash)))

	return subtle.ConstantTimeCompare(bHash, newHash) == 1, nil
}

func NewArgon2idHasher() *Argon2idHasher {
	return &Argon2idHasher{
		Time:    2,
		Memory:  65536,
		Threads: 4,
		Length:  32,
	}
}
