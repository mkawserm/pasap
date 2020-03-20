package pasap

// ByteBasedEncoderCredentials implements EncoderCredentials
type ByteBasedEncoderCredentials struct {
	Salt     []byte
	Password []byte
}

// ReadSalt from the given bytes
func (b *ByteBasedEncoderCredentials) ReadSalt() (salt []byte, err error) {
	if len(b.Salt) == 0 {
		return nil, ErrInvalidData
	}

	return b.Salt, nil
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

// ReadPassword from the given bytes
func (b *ByteBasedVerifierCredentials) ReadPassword() (password []byte, err error) {
	if len(b.Password) == 0 {
		return nil, ErrInvalidData
	}

	return b.Password, nil
}

// ReadEncodedKey from the given bytes
func (b *ByteBasedVerifierCredentials) ReadEncodedKey() (encodedKey []byte, err error) {
	if len(b.EncodedKey) == 0 {
		return nil, ErrInvalidData
	}

	return b.EncodedKey, nil
}
