package crypto

// PlainCrypt describes a plain crypt which will not encrypt the data.
type PlainCrypt struct {
}

func (c *PlainCrypt) Prepare() error {
	return nil
}

// CreatePlainCrypt returns an plain crypt
func CreatePlainCrypt() *PlainCrypt {
	return &PlainCrypt{}
}

func (c *PlainCrypt) Encrypt(data []byte) ([]byte, error) {
	return data, nil
}

func (c *PlainCrypt) Decrypt(data []byte) ([]byte, error) {
	return data, nil
}

func (c *PlainCrypt) Method() Method {
	return MethodPlain
}

func (c *PlainCrypt) Cost() int {
	return 0
}
