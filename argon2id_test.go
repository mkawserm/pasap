package pasap

import (
	"testing"
)

func TestArgon2idHasher_EncodeNilPassword(t *testing.T) {
	a := NewArgon2idHasher()
	_, _, err := a.Encode(&ByteBasedEncoderCredentials{
		Salt:     nil,
		Password: nil,
	})

	if err != ErrInvalidData {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestArgon2idHasher_EncodeSalt(t *testing.T) {
	a := NewArgon2idHasher()
	_, _, err := a.Encode(&ByteBasedEncoderCredentials{
		Salt:     nil,
		Password: []byte("password"),
	})

	if err != ErrInvalidData {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestNewArgon2idHasher(t *testing.T) {
	a := NewArgon2idHasher()

	if a == nil {
		t.Errorf("nil pointer returned, expected pointer of Argon2idHasher")
		return
	}

	if a.Name() != "argon2id" {
		t.Errorf("expected name argon2id, name does not match")
		return
	}

	{
		secretKey, encodedKey, err := a.Encode(&ByteBasedEncoderCredentials{
			Salt:     []byte("123456789"),
			Password: []byte("pass"),
		})
		if len(secretKey) != 32 {
			t.Errorf("expected secret key length 32, but got %d", len(secretKey))
			return
		}

		_, ok, err := a.Verify(&ByteBasedVerifierCredentials{
			Password:   []byte("pass"),
			EncodedKey: encodedKey,
		})

		if err != nil {
			t.Errorf("error: %v", err)
			return
		}

		if !ok {
			t.Errorf("verification is not working")
			return
		}
	}

	{
		secretKey, encodedKey, err := a.Encode(&ByteBasedEncoderCredentials{
			Salt:     nil,
			Password: []byte("pass"),
		})
		if err != ErrInvalidData {
			t.Errorf("Unexpected error: %v", err)
			return
		}
		//fmt.Println(string(encodedKey))
		if len(secretKey) != 0 {
			t.Errorf("expected secret key length 0, but got %d", len(secretKey))
			return
		}

		if len(encodedKey) != 0 {
			t.Errorf("expected encoded key length 0, but go %d", len(secretKey))
			return
		}
	}
}

func TestArgon2idHasher_Verify(t *testing.T) {
	{
		data := "argon2id$v=19$m=65536,t=2,p=4$MTIzNDU2Nzg5$XSL8cCbrmp0URjVS79dzQodzLMkyGza22ob2G9ZMGXo"
		c := &ByteBasedVerifierCredentials{
			Password:   []byte("pass2"),
			EncodedKey: []byte(data),
		}
		a := NewArgon2idHasher()
		_, ok, _ := a.Verify(c)

		if ok {
			t.Errorf("Verify should not be ok")
		}
	}

	{
		data := "new$argon2id$v=19$m=65536,t=2,p=4$MTIzNDU2Nzg5$XSL8cCbrmp0URjVS79dzQodzLMkyGza22ob2G9ZMGXo"
		c := &ByteBasedVerifierCredentials{
			Password:   []byte("pass2"),
			EncodedKey: []byte(data),
		}
		a := NewArgon2idHasher()
		_, _, err := a.Verify(c)
		if err != ErrHashComponentMismatch {
			t.Errorf("Error should be ErrHashComponentMismatch but got %v", err)
		}
	}

	{
		data := "argon3id$v=19$m=65536,t=2,p=4$MTIzNDU2Nzg5$XSL8cCbrmp0URjVS79dzQodzLMkyGza22ob2G9ZMGXo"
		c := &ByteBasedVerifierCredentials{
			Password:   []byte("pass2"),
			EncodedKey: []byte(data),
		}
		a := NewArgon2idHasher()
		_, _, err := a.Verify(c)
		if err != ErrAlgorithmMismatch {
			t.Errorf("Error should be ErrAlgorithmMismatch but got %v", err)
		}
	}

	{
		data := "argon2id$v=smile$m=65536,t=2,p=4$MTIzNDU2Nzg5$XSL8cCbrmp0URjVS79dzQodzLMkyGza22ob2G9ZMGXo"
		c := &ByteBasedVerifierCredentials{
			Password:   []byte("pass2"),
			EncodedKey: []byte(data),
		}
		a := NewArgon2idHasher()
		_, _, err := a.Verify(c)
		if err != ErrHashComponentUnreadable {
			t.Errorf("Error should be ErrHashComponentUnreadable but got %v", err)
		}
	}

	{
		data := "argon2id$v=20$m=65536,t=2,p=4$MTIzNDU2Nzg5$XSL8cCbrmp0URjVS79dzQodzLMkyGza22ob2G9ZMGXo"
		c := &ByteBasedVerifierCredentials{
			Password:   []byte("pass2"),
			EncodedKey: []byte(data),
		}
		a := NewArgon2idHasher()
		_, _, err := a.Verify(c)
		if err != ErrIncompatibleVersion {
			t.Errorf("Error should be ErrIncompatibleVersion but got %v", err)
		}
	}

	{
		data := "argon2id$v=19$m=smile,t=2,p=4$MTIzNDU2Nzg5$XSL8cCbrmp0URjVS79dzQodzLMkyGza22ob2G9ZMGXo"
		c := &ByteBasedVerifierCredentials{
			Password:   []byte("pass2"),
			EncodedKey: []byte(data),
		}
		a := NewArgon2idHasher()
		_, _, err := a.Verify(c)
		if err != ErrHashComponentUnreadable {
			t.Errorf("Error should be ErrHashComponentUnreadable but got %v", err)
		}
	}

	{
		data := "argon2id$v=19$m=65536,t=2,p=4$2$XSL8cCbrmp0URjVS79dzQodzLMkyGza22ob2G9ZMGXo"
		c := &ByteBasedVerifierCredentials{
			Password:   []byte("pass2"),
			EncodedKey: []byte(data),
		}

		a := NewArgon2idHasher()
		_, _, err := a.Verify(c)
		if err != ErrHashComponentUnreadable {
			t.Errorf("Error should be ErrHashComponentUnreadable but got %v", err)
		}
	}

	{
		data := "argon2id$v=19$m=65536,t=2,p=4$MTIzNDU2Nzg5$1"
		c := &ByteBasedVerifierCredentials{
			Password:   []byte("pass2"),
			EncodedKey: []byte(data),
		}
		a := NewArgon2idHasher()
		_, _, err := a.Verify(c)
		if err != ErrHashComponentUnreadable {
			t.Errorf("Error should be ErrHashComponentUnreadable but got %v", err)
		}
	}

}

func TestArgon2idHasher_VerifyNilPassword(t *testing.T) {
	a := NewArgon2idHasher()
	_, _, err := a.Verify(&ByteBasedVerifierCredentials{
		Password:   nil,
		EncodedKey: nil,
	})

	if err != ErrInvalidData {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestArgon2idHasher_VerifyNilEncodedKey(t *testing.T) {
	a := NewArgon2idHasher()
	_, _, err := a.Verify(&ByteBasedVerifierCredentials{
		Password:   []byte("password"),
		EncodedKey: nil,
	})

	if err != ErrInvalidData {
		t.Errorf("unexpected error: %v", err)
	}
}
