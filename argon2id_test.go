package pasap

import (
	"testing"
)

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

	secretKey, encodedKey := a.Encode([]byte("pass"), []byte("123456789"))

	if len(secretKey) != 32 {
		t.Errorf("expected secret key length 32, but got %d", len(secretKey))
		return
	}

	ok, err := a.Verify([]byte("pass"), encodedKey)

	if err != nil {
		t.Errorf("error: %v", err)
		return
	}

	if !ok {
		t.Errorf("verification is not working")
		return
	}
}

func TestArgon2idHasher_Verify(t *testing.T) {
	{
		data := "argon2id$v=19$m=65536,t=2,p=4$MTIzNDU2Nzg5$XSL8cCbrmp0URjVS79dzQodzLMkyGza22ob2G9ZMGXo"
		a := NewArgon2idHasher()
		ok, _ := a.Verify([]byte("pass2"), []byte(data))

		if ok {
			t.Errorf("Verify should not be ok")
		}
	}

	{
		data := "new$argon2id$v=19$m=65536,t=2,p=4$MTIzNDU2Nzg5$XSL8cCbrmp0URjVS79dzQodzLMkyGza22ob2G9ZMGXo"
		a := NewArgon2idHasher()
		_, err := a.Verify([]byte("pass2"), []byte(data))
		if err != ErrHashComponentMismatch {
			t.Errorf("Error should be ErrHashComponentMismatch but got %v", err)
		}
	}

	{
		data := "argon3id$v=19$m=65536,t=2,p=4$MTIzNDU2Nzg5$XSL8cCbrmp0URjVS79dzQodzLMkyGza22ob2G9ZMGXo"
		a := NewArgon2idHasher()
		_, err := a.Verify([]byte("pass2"), []byte(data))
		if err != ErrAlgorithmMismatch {
			t.Errorf("Error should be ErrAlgorithmMismatch but got %v", err)
		}
	}

	{
		data := "argon2id$v=smile$m=65536,t=2,p=4$MTIzNDU2Nzg5$XSL8cCbrmp0URjVS79dzQodzLMkyGza22ob2G9ZMGXo"
		a := NewArgon2idHasher()
		_, err := a.Verify([]byte("pass2"), []byte(data))
		if err != ErrHashComponentUnreadable {
			t.Errorf("Error should be ErrHashComponentUnreadable but got %v", err)
		}
	}

	{
		data := "argon2id$v=20$m=65536,t=2,p=4$MTIzNDU2Nzg5$XSL8cCbrmp0URjVS79dzQodzLMkyGza22ob2G9ZMGXo"
		a := NewArgon2idHasher()
		_, err := a.Verify([]byte("pass2"), []byte(data))
		if err != ErrIncompatibleVersion {
			t.Errorf("Error should be ErrIncompatibleVersion but got %v", err)
		}
	}

	{
		data := "argon2id$v=19$m=smile,t=2,p=4$MTIzNDU2Nzg5$XSL8cCbrmp0URjVS79dzQodzLMkyGza22ob2G9ZMGXo"
		a := NewArgon2idHasher()
		_, err := a.Verify([]byte("pass2"), []byte(data))
		if err != ErrHashComponentUnreadable {
			t.Errorf("Error should be ErrHashComponentUnreadable but got %v", err)
		}
	}

}
