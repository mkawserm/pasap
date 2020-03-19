package pasap

// AlgorithmName basic interface
type AlgorithmName interface {
	Name() string
}

// PasswordEncoder basic interface
type PasswordEncoder interface {
	Encode(password, salt []byte) (fixedLengthKey, encodedKey []byte)
}

// PasswordVerifier basic interface
type PasswordVerifier interface {
	Verify(password, encodedKey []byte) (bool, error)
}

// PasswordHasher basic interface
type PasswordHasher interface {
	AlgorithmName
	PasswordEncoder
	PasswordVerifier
}
