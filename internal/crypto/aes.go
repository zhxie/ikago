package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// AESCFBCrypto describes an AES-256-CFB crypto
type AESCFBCrypto struct {
	Key       []byte
	IV        []byte
	block     cipher.Block
	encrypter cipher.Stream
	decrypter cipher.Stream
}

func (c *AESCFBCrypto) Prepare() error {
	var err error

	if len(c.Key) != 32 {
		return fmt.Errorf("create crypto: %w", fmt.Errorf("invalid key"))
	}

	// Cipher
	c.block, err = aes.NewCipher(c.Key)
	if err != nil {
		return fmt.Errorf("create crypto: %w", fmt.Errorf("create cipher: %w", err))
	}

	c.encrypter = cipher.NewCFBEncrypter(c.block, c.IV)
	c.decrypter = cipher.NewCFBDecrypter(c.block, c.IV)

	return nil
}

func (c *AESCFBCrypto) Encrypt(data []byte) ([]byte, error) {
	result := make([]byte, len(data))

	c.encrypter.XORKeyStream(data, result)

	return result, nil
}

func (c *AESCFBCrypto) Decrypt(data []byte) ([]byte, error) {
	result := make([]byte, len(data))

	c.decrypter.XORKeyStream(data, result)

	return result, nil
}

func (c *AESCFBCrypto) Method() Method {
	return MethodAESCFB
}

// AESGCMCrypto describes an AES-GCM crypto
type AESGCMCrypto struct {
	Key   []byte
	block cipher.Block
	aead  cipher.AEAD
}

func (c *AESGCMCrypto) Prepare() error {
	var err error

	// Cipher
	c.block, err = aes.NewCipher(c.Key)
	if err != nil {
		return fmt.Errorf("create crypto: %w", fmt.Errorf("create cipher: %w", err))
	}

	// AEAD
	c.aead, err = cipher.NewGCM(c.block)
	if err != nil {
		return fmt.Errorf("create crypto: %w", fmt.Errorf("create aead: %w", err))
	}

	return nil
}

func (c *AESGCMCrypto) Encrypt(data []byte) ([]byte, error) {
	nonce, err := GenerateNonce(c.aead.NonceSize())
	if err != nil {
		return nil, fmt.Errorf("encrypt: %w", err)
	}

	result := c.aead.Seal(nil, nonce, data, nil)
	result = append(nonce, result...)

	return result, nil
}

func (c *AESGCMCrypto) Decrypt(data []byte) ([]byte, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("decrypt: %w", fmt.Errorf("missing nonce"))
	}
	nonce := data[:12]

	result, err := c.aead.Open(nil, nonce, data[12:], nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return result, nil
}

func (c *AESGCMCrypto) Method() Method {
	return MethodAESGCM
}
