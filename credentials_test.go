package pasap

import (
	"bytes"
	"testing"
)

func TestByteBasedEncoderCredentials_ReadPassword(t *testing.T) {
	{
		a := &ByteBasedEncoderCredentials{
			Salt:     nil,
			Password: []byte("TEST"),
		}

		password, err := a.ReadPassword()

		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		if !bytes.Equal(password, a.Password) {
			t.Errorf("Password mismatch. expected behavior password should match")
		}
	}

	{
		a := &ByteBasedEncoderCredentials{
			Salt:     nil,
			Password: nil,
		}

		_, err := a.ReadPassword()

		if err != ErrInvalidData {
			t.Errorf("Unexpected error: %v", err)
		}
	}

}

func TestByteBasedEncoderCredentials_ReadSalt(t *testing.T) {
	{
		a := &ByteBasedEncoderCredentials{
			Salt: []byte("TEST"),
		}

		salt, err := a.ReadSalt()

		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		if !bytes.Equal(salt, a.Salt) {
			t.Errorf("Salt mismatch. expected behavior salt should match")
		}
	}

	{
		a := &ByteBasedEncoderCredentials{
			Salt:     nil,
			Password: nil,
		}

		_, err := a.ReadSalt()

		if err != ErrInvalidData {
			t.Errorf("Unexpected error: %v", err)
		}
	}
}

func TestByteBasedVerifierCredentials_ReadPassword(t *testing.T) {
	{
		a := &ByteBasedVerifierCredentials{
			EncodedKey: nil,
			Password:   []byte("TEST"),
		}

		password, err := a.ReadPassword()

		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		if !bytes.Equal(password, a.Password) {
			t.Errorf("Password mismatch. expected behavior password should match")
		}
	}

	{
		a := &ByteBasedVerifierCredentials{
			EncodedKey: nil,
			Password:   nil,
		}

		_, err := a.ReadPassword()

		if err != ErrInvalidData {
			t.Errorf("Unexpected error: %v", err)
		}
	}

}

func TestByteBasedVerifierCredentials_ReadEncodedKey(t *testing.T) {
	{
		a := &ByteBasedVerifierCredentials{
			EncodedKey: []byte("TEST"),
		}

		encodedKey, err := a.ReadEncodedKey()

		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		if !bytes.Equal(encodedKey, a.EncodedKey) {
			t.Errorf("encodedKey mismatch. expected behavior encodedKey should match")
		}
	}

	{
		a := &ByteBasedVerifierCredentials{
			EncodedKey: nil,
			Password:   nil,
		}

		_, err := a.ReadEncodedKey()

		if err != ErrInvalidData {
			t.Errorf("Unexpected error: %v", err)
		}
	}
}
