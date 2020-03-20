package pasap_test

import (
	"fmt"
	"github.com/mkawserm/pasap"
)

func ExampleNewArgon2idHasher() {
	a := pasap.NewArgon2idHasher()
	ec := &pasap.ByteBasedEncoderCredentials{
		Salt:     []byte("123456789"),
		Password: []byte("pass"),
	}
	secretKey, encodedKey, err := a.Encode(ec)

	fmt.Printf("Secret key: %v\n", secretKey)
	fmt.Printf("Encoded key: %v\n", encodedKey)

	vc := &pasap.ByteBasedVerifierCredentials{
		Password:   []byte("pass"),
		EncodedKey: encodedKey,
	}
	_, ok, err := a.Verify(vc)
	if err != nil {
		panic(err)
	}

	if ok {
		fmt.Println("Valid password")
	}
}
