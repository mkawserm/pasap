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
