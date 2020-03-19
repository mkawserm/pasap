package pasap

import (
	"io"
	"testing"
)

func TestGetSaltWithoutReader(t *testing.T) {
	s := GetSalt(5, nil)
	if len(s) != 5 {
		t.Errorf("Expected salt length 5, got %d", len(s))
	}
}

type errorReader struct {
}

func (e *errorReader) Read([]byte) (n int, err error) {
	return -1, io.ErrUnexpectedEOF
}

func TestGetSaltWithReader(t *testing.T) {
	s := GetSalt(5, &errorReader{})
	if len(s) != 0 {
		t.Errorf("Expected salt length 0, got %d", len(s))
	}
}
