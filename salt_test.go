package pasap

import (
	"testing"
)

func TestGenerateRandomSalt(t *testing.T) {
	s := GenerateRandomSalt(5)
	//fmt.Println(s)
	if len(s) != 5 {
		t.Errorf("Expected salt length 5, got %d", len(s))
	}
}
