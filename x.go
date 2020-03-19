package pasap

import "errors"

var (
	ErrHashComponentUnreadable = errors.New("pasap: unreadable component in hashed password")
	ErrHashComponentMismatch   = errors.New("pasap: hashed password components mismatch")
	ErrAlgorithmMismatch       = errors.New("pasap: algorithm mismatch")
	ErrIncompatibleVersion     = errors.New("pasap: incompatible version")
)
