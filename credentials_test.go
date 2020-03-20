package pasap

import (
	"bytes"
	"testing"
)

func TestByteBasedEncoderCredentials_ReadPassword(t *testing.T) {
	t.Helper()

	t.Run("Password Set and Read", func(t *testing.T) {
		a := &ByteBasedEncoderCredentials{}
		_ = a.SetPassword([]byte("TEST"))
		password, err := a.ReadPassword()
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if !bytes.Equal(password, a.Password) {
			t.Fatalf("Password mismatch. expected behavior password should match")
		}
	})

	t.Run("ReadPassword error validation", func(t *testing.T) {
		a := &ByteBasedEncoderCredentials{}
		_, err := a.ReadPassword()
		if err != ErrInvalidData {
			t.Fatalf("Unexpected error: %v", err)
		}
	})
}

func TestByteBasedEncoderCredentials_ReadSalt(t *testing.T) {
	t.Helper()

	t.Run("Salt set and read", func(t *testing.T) {
		a := &ByteBasedEncoderCredentials{}
		_ = a.SetSalt([]byte("TEST"))
		salt, err := a.ReadSalt()
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if !bytes.Equal(salt, a.Salt) {
			t.Fatalf("Salt mismatch. expected behavior salt should match")
		}
	})

	t.Run("ReadSalt error validation", func(t *testing.T) {
		a := &ByteBasedEncoderCredentials{}
		_, err := a.ReadSalt()
		if err != ErrInvalidData {
			t.Fatalf("Unexpected error: %v", err)
		}
	})

}

func TestByteBasedVerifierCredentials_ReadPassword(t *testing.T) {
	t.Helper()

	t.Run("Password set and read", func(t *testing.T) {
		a := &ByteBasedVerifierCredentials{}
		_ = a.SetPassword([]byte("TEST"))
		password, err := a.ReadPassword()
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if !bytes.Equal(password, a.Password) {
			t.Fatalf("Password mismatch. expected behavior password should match")
		}
	})

	t.Run("ReadPassword error validation", func(t *testing.T) {
		a := &ByteBasedVerifierCredentials{}
		_, err := a.ReadPassword()
		if err != ErrInvalidData {
			t.Fatalf("Unexpected error: %v", err)
		}
	})
}

func TestByteBasedVerifierCredentials_ReadEncodedKey(t *testing.T) {
	t.Helper()

	t.Run("EncodedKey set and read", func(t *testing.T) {
		a := &ByteBasedVerifierCredentials{}
		_ = a.SetEncodedKey([]byte("TEST"))
		encodedKey, err := a.ReadEncodedKey()
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if !bytes.Equal(encodedKey, a.EncodedKey) {
			t.Fatalf("encodedKey mismatch. expected behavior encodedKey should match")
		}
	})

	t.Run("ReadEncodedKey error validation", func(t *testing.T) {
		a := &ByteBasedVerifierCredentials{}
		_, err := a.ReadEncodedKey()
		if err != ErrInvalidData {
			t.Fatalf("Unexpected error: %v", err)
		}
	})
}
