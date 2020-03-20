package pasap

import "errors"

var (
	// ErrHashComponentUnreadable occurs when unreadable component in hashed password
	ErrHashComponentUnreadable = errors.New("pasap: unreadable component in hashed password")

	// ErrHashComponentMismatch occurs when hashed password components does not match
	ErrHashComponentMismatch = errors.New("pasap: hashed password components mismatch")

	// ErrAlgorithmMismatch occurs when algorithm does not match
	ErrAlgorithmMismatch = errors.New("pasap: algorithm mismatch")

	// ErrIncompatibleVersion occurs when version in to compatible
	ErrIncompatibleVersion = errors.New("pasap: incompatible version")

	// ErrInvalidData occurs when given data is not valid, normally for
	// salt, password and encoded key
	ErrInvalidData = errors.New("pasap: invalid data")
)
