package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

// AESCFBCrypto describes an AES-CFB crypto
type AESCFBCrypto struct {
	block     cipher.Block
	encrypter cipher.Stream
	decrypter cipher.Stream
}

// CreateAESCFBCrypto returns an AES-CFB crypto by given key and IV
func CreateAESCFBCrypto(key, iv []byte) (*AESCFBCrypto, error) {
	// Cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}

	encrypter := cipher.NewCFBEncrypter(block, iv)
	decrypter := cipher.NewCFBDecrypter(block, iv)

	return &AESCFBCrypto{
		block:     block,
		encrypter: encrypter,
		decrypter: decrypter,
	}, nil
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
	block cipher.Block
	aead  cipher.AEAD
}

// CreateAESGCMCrypto returns an AES-GCM crypto by given key
func CreateAESGCMCrypto(key []byte) (*AESGCMCrypto, error) {
	// Cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}

	// AEAD
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}

	return &AESGCMCrypto{
		block: block,
		aead:  aead,
	}, nil
}

func (c *AESGCMCrypto) Encrypt(data []byte) ([]byte, error) {
	nonce, err := GenerateNonce(c.aead.NonceSize())
	if err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	result := c.aead.Seal(nil, nonce, data, nil)
	result = append(nonce, result...)

	return result, nil
}

func (c *AESGCMCrypto) Decrypt(data []byte) ([]byte, error) {
	size := c.aead.NonceSize()
	if len(data) < size {
		return nil, errors.New("missing nonce")
	}
	nonce := data[:size]

	result, err := c.aead.Open(nil, nonce, data[size:], nil)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}

	return result, nil
}

func (c *AESGCMCrypto) Method() Method {
	return MethodAESGCM
}
