package pasap

// AlgorithmName basic interface
type AlgorithmName interface {
	Name() string
}

// PasswordEncoder basic interface
type PasswordEncoder interface {
	Encode(password, salt []byte) (secretKey, encodedKey []byte)
}

// PasswordVerifier basic interface
type PasswordVerifier interface {
	Verify(password, encodedKey []byte) ([]byte, bool, error)
}

// PasswordHasher basic interface
type PasswordHasher interface {
	AlgorithmName
	PasswordEncoder
	PasswordVerifier
}
