pasap 
-------------------------------------------------
[![GoDoc](https://godoc.org/github.com/mkawserm/pasap?status.svg)](https://godoc.org/github.com/mkawserm/pasap)
[![Build Status](https://travis-ci.com/mkawserm/pasap.svg?branch=master)](https://travis-ci.com/mkawserm/pasap)
[![Go Report Card](https://goreportcard.com/badge/github.com/mkawserm/pasap)](https://goreportcard.com/report/github.com/mkawserm/pasap)
[![Coverage Status](https://coveralls.io/repos/github/mkawserm/pasap/badge.svg?branch=master)](https://coveralls.io/github/mkawserm/pasap?branch=master)

-------------------------------------------------

Package pasap provides a way to derive fixed length
cryptographically secure secret key from password
using different key derivation algorithm, provides an encoded string and
verify the password against the encoded string

# Usage

> `➜ go get github.com/mkawserm/pasap`

```go
package main

import "fmt"
import "github.com/mkawserm/pasap"

func main()  {
	a := pasap.NewArgon2idHasher()
	ec := &pasap.ByteBasedEncoderCredentials{
		Salt:     []byte("123456789"),
		Password: []byte("pass"),
	}
	secretKey, encodedKey,err := a.Encode(ec)

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
```