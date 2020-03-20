package pasap

type ByteBasedEncoderCredentials struct {
	Salt     []byte
	Password []byte
}

func (b *ByteBasedEncoderCredentials) ReadSalt() (salt []byte, err error) {
	if len(b.Salt) == 0 {
		return nil, ErrInvalidData
	}

	return b.Salt, nil
}

func (b *ByteBasedEncoderCredentials) ReadPassword() (password []byte, err error) {
	if len(b.Password) == 0 {
		return nil, ErrInvalidData
	}

	return b.Password, nil
}

type ByteBasedVerifierCredentials struct {
	Password   []byte
	EncodedKey []byte
}

func (b *ByteBasedVerifierCredentials) ReadPassword() (password []byte, err error) {
	if len(b.Password) == 0 {
		return nil, ErrInvalidData
	}

	return b.Password, nil
}

func (b *ByteBasedVerifierCredentials) ReadEncodedKey() (encodedKey []byte, err error) {
	if len(b.EncodedKey) == 0 {
		return nil, ErrInvalidData
	}

	return b.EncodedKey, nil
}
