package pasap

// ByteBasedEncoderCredentials implements EncoderCredentials
type ByteBasedEncoderCredentials struct {
	Salt     []byte
	Password []byte
}

// SetSalt updates internal salt data
func (b *ByteBasedEncoderCredentials) SetSalt(salt []byte) error {
	b.Salt = salt
	return nil
}

// ReadSalt from the given bytes
func (b *ByteBasedEncoderCredentials) ReadSalt() (salt []byte, err error) {
	if len(b.Salt) == 0 {
		return nil, ErrInvalidData
	}

	return b.Salt, nil
}

// SetPassword updates internal password data
func (b *ByteBasedEncoderCredentials) SetPassword(password []byte) error {
	b.Password = password
	return nil
}

// ReadPassword from the given bytes
func (b *ByteBasedEncoderCredentials) ReadPassword() (password []byte, err error) {
	if len(b.Password) == 0 {
		return nil, ErrInvalidData
	}

	return b.Password, nil
}

// ByteBasedVerifierCredentials implements VerifierCredentials
type ByteBasedVerifierCredentials struct {
	Password   []byte
	EncodedKey []byte
}

// SetPassword updates internal password data
func (b *ByteBasedVerifierCredentials) SetPassword(password []byte) error {
	b.Password = password
	return nil
}

// ReadPassword from the given bytes
func (b *ByteBasedVerifierCredentials) ReadPassword() (password []byte, err error) {
	if len(b.Password) == 0 {
		return nil, ErrInvalidData
	}

	return b.Password, nil
}

// SetEncodedKey updates internal encoded key data
func (b *ByteBasedVerifierCredentials) SetEncodedKey(encodedKey []byte) error {
	b.EncodedKey = encodedKey
	return nil
}

// ReadEncodedKey from the given bytes
func (b *ByteBasedVerifierCredentials) ReadEncodedKey() (encodedKey []byte, err error) {
	if len(b.EncodedKey) == 0 {
		return nil, ErrInvalidData
	}

	return b.EncodedKey, nil
}
