package pasap

// EncoderCredentials interface defines ReadSalt and ReadPassword methods
type EncoderCredentials interface {
	ReadSalt() (salt []byte, err error)
	ReadPassword() (password []byte, err error)
}

// VerifierCredentials interface defines ReadPassword and ReadEncodedKey methods
type VerifierCredentials interface {
	ReadPassword() (password []byte, err error)
	ReadEncodedKey() (encodedKey []byte, err error)
}

// AlgorithmName basic interface
type AlgorithmName interface {
	Name() string
}

// PasswordEncoder basic interface
type PasswordEncoder interface {
	Encode(encoderCredentials EncoderCredentials) (secretKey, encodedKey []byte, err error)
}

// PasswordVerifier basic interface
type PasswordVerifier interface {
	Verify(verifierCredentials VerifierCredentials) (secretKey []byte, ok bool, err error)
}

// PasswordHasher basic interface
type PasswordHasher interface {
	AlgorithmName
	PasswordEncoder
	PasswordVerifier
}
