package pasap

import "errors"

var (
	// ErrHashComponentUnreadable
	ErrHashComponentUnreadable = errors.New("pasap: unreadable component in hashed password")

	// ErrHashComponentMismatch
	ErrHashComponentMismatch = errors.New("pasap: hashed password components mismatch")

	// ErrAlgorithmMismatch
	ErrAlgorithmMismatch = errors.New("pasap: algorithm mismatch")

	// ErrIncompatibleVersion
	ErrIncompatibleVersion = errors.New("pasap: incompatible version")
)
