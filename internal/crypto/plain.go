package crypto

// PlainCrypto describes a plain crypto which will not encrypt the data
type PlainCrypto struct {
}

func (c *PlainCrypto) Prepare() error {
	return nil
}

func (c *PlainCrypto) Encrypt(data []byte) ([]byte, error) {
	return data, nil
}

func (c *PlainCrypto) Decrypt(data []byte) ([]byte, error) {
	return data, nil
}

func (c *PlainCrypto) Method() Method {
	return MethodPlain
}
