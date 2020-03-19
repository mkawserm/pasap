package pasap_test

import (
	"fmt"
	"github.com/mkawserm/pasap"
)

func ExampleNewArgon2idHasher() {
	a := pasap.NewArgon2idHasher()
	secretKey, encodedKey := a.Encode([]byte("pass"), []byte("123456789"))

	fmt.Printf("Secret key: %v\n", secretKey)
	fmt.Printf("Encoded key: %v\n", encodedKey)

	ok, err := a.Verify([]byte("pass"), encodedKey)
	if err != nil {
		panic(err)
	}

	if ok {
		fmt.Println("Valid password")
	}
}
