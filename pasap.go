package pasap

// EncoderCredentialsReader interface defines ReadSalt and ReadPassword methods
type EncoderCredentialsReader interface {
	ReadSalt() (salt []byte, err error)
	ReadPassword() (password []byte, err error)
}

// EncoderCredentialsWriter interface defines SetSalt and SetPassword methods
type EncoderCredentialsWriter interface {
	SetSalt(salt []byte) error
	SetPassword(password []byte) error
}

// EncoderCredentialsRW interface combines together EncoderCredentialsReader and EncoderCredentialsWriter
type EncoderCredentialsRW interface {
	EncoderCredentialsReader
	EncoderCredentialsWriter
}

// VerifierCredentialsReader interface defines ReadPassword and ReadEncodedKey methods
type VerifierCredentialsReader interface {
	ReadPassword() (password []byte, err error)
	ReadEncodedKey() (encodedKey []byte, err error)
}

// VerifierCredentialsWriter interface defines SetPassword and SetEncodedKey methods
type VerifierCredentialsWriter interface {
	SetPassword(password []byte) error
	SetEncodedKey(encodedKey []byte) error
}

// VerifierCredentialsRW interface combines VerifierCredentialsReader and VerifierCredentialsWriter
type VerifierCredentialsRW interface {
	VerifierCredentialsReader
	VerifierCredentialsWriter
}

// AlgorithmName basic interface
type AlgorithmName interface {
	Name() string
}

// AlgorithmVersion basic interface
type AlgorithmVersion interface {
	Version() int
}

// AlgorithmParameters basic interface
type AlgorithmParameters interface {
	Parameters() string
}

// PasswordEncoder basic interface
type PasswordEncoder interface {
	Encode(encoderCredentials EncoderCredentialsReader) (secretKey, encodedKey []byte, err error)
}

// PasswordVerifier basic interface
type PasswordVerifier interface {
	Verify(verifierCredentials VerifierCredentialsReader) (secretKey []byte, ok bool, err error)
}

// PasswordHasher basic interface
type PasswordHasher interface {
	AlgorithmName
	AlgorithmVersion
	AlgorithmParameters
	PasswordEncoder
	PasswordVerifier
}
