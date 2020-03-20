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

// Name returns Argon2idHasher name
func (a *Argon2idHasher) Name() string {
	return "argon2id"
}

func (a *Argon2idHasher) Version() int {
	return argon2.Version
}

func (a *Argon2idHasher) Parameters() string {
	s := fmt.Sprintf("m=%d,t=%d,p=%d",
		a.Memory,
		a.Time,
		a.Threads,
	)
	return s
}

// Encode the password using argon2.IDKey algorithm
func (a *Argon2idHasher) Encode(encoderCredentials EncoderCredentialsReader) (secretKey, encodedKey []byte, err error) {
	var password []byte
	var salt []byte

	password, err = encoderCredentials.ReadPassword()
	if err != nil {
		return nil, nil, err
	}

	salt, err = encoderCredentials.ReadSalt()
	if err != nil {
		return nil, nil, err
	}

	secretKey = argon2.IDKey(password, salt, a.Time, a.Memory, a.Threads, a.Length)
	hash := argon2.IDKey(secretKey, salt, a.Time, a.Memory, a.Threads, a.Length)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	s := fmt.Sprintf("%s$v=%d$%s$%s$%s",
		a.Name(),
		a.Version(),
		a.Parameters(),
		b64Salt,
		b64Hash,
	)
	encodedKey = []byte(s)

	return secretKey, encodedKey, err
}

// Verify the password against the encoded key
func (a *Argon2idHasher) Verify(verifierCredentials VerifierCredentialsReader) (secretKey []byte, ok bool, err error) {
	var password []byte
	var encodedKey []byte

	password, err = verifierCredentials.ReadPassword()
	if err != nil {
		return nil, false, err
	}

	encodedKey, err = verifierCredentials.ReadEncodedKey()
	if err != nil {
		return nil, false, err
	}

	s := strings.Split(string(encodedKey), "$")

	if len(s) != 5 {
		return nil, false, ErrHashComponentMismatch
	}

	algorithm, version, params, salt, hash := s[0], s[1], s[2], s[3], s[4]

	if algorithm != a.Name() {
		return nil, false, ErrAlgorithmMismatch
	}

	var v int

	_, err = fmt.Sscanf(version, "v=%d", &v)

	if err != nil {
		return nil, false, ErrHashComponentUnreadable
	}

	if v != a.Version() {
		return nil, false, ErrIncompatibleVersion
	}

	var time, memory uint32
	var threads uint8

	_, err = fmt.Sscanf(string(params), "m=%d,t=%d,p=%d", &memory, &time, &threads)

	if err != nil {
		return nil, false, ErrHashComponentUnreadable
	}

	var bSalt []byte
	bSalt, err = base64.RawStdEncoding.DecodeString(salt)

	if err != nil {
		return nil, false, ErrHashComponentUnreadable
	}

	var bHash []byte
	bHash, err = base64.RawStdEncoding.DecodeString(hash)

	if err != nil {
		return nil, false, ErrHashComponentUnreadable
	}

	secretKey = argon2.IDKey(password, bSalt, time, memory, threads, uint32(len(bHash)))
	newHash := argon2.IDKey(secretKey, bSalt, time, memory, threads, uint32(len(bHash)))

	return secretKey, subtle.ConstantTimeCompare(bHash, newHash) == 1, nil
}

// NewArgon2idHasher returns a new Argon2idHasher instance
func NewArgon2idHasher() *Argon2idHasher {
	return &Argon2idHasher{
		Time:    2,
		Memory:  65536,
		Threads: 4,
		Length:  32,
	}
}
