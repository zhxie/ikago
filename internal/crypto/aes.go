package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

// AESCFBCrypt describes an AES-CFB crypt.
type AESCFBCrypt struct {
	block     cipher.Block
	encrypter cipher.Stream
	decrypter cipher.Stream
}

// CreateAESCFBCrypt returns an AES-CFB crypt by given key and IV.
func CreateAESCFBCrypt(key, iv []byte) (*AESCFBCrypt, error) {
	// Cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}

	encrypter := cipher.NewCFBEncrypter(block, iv)
	decrypter := cipher.NewCFBDecrypter(block, iv)

	return &AESCFBCrypt{
		block:     block,
		encrypter: encrypter,
		decrypter: decrypter,
	}, nil
}

func (c *AESCFBCrypt) Encrypt(data []byte) ([]byte, error) {
	result := make([]byte, len(data))

	c.encrypter.XORKeyStream(data, result)

	return result, nil
}

func (c *AESCFBCrypt) Decrypt(data []byte) ([]byte, error) {
	result := make([]byte, len(data))

	c.decrypter.XORKeyStream(data, result)

	return result, nil
}

func (c *AESCFBCrypt) Method() Method {
	return MethodAESCFB
}

// AESGCMCrypt describes an AES-GCM crypt.
type AESGCMCrypt struct {
	block cipher.Block
	aead  cipher.AEAD
}

// CreateAESGCMCrypt returns an AES-GCM crypt by given key.
func CreateAESGCMCrypt(key []byte) (*AESGCMCrypt, error) {
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

	return &AESGCMCrypt{
		block: block,
		aead:  aead,
	}, nil
}

func (c *AESGCMCrypt) Encrypt(data []byte) ([]byte, error) {
	nonce, err := GenerateNonce(c.aead.NonceSize())
	if err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	result := c.aead.Seal(nil, nonce, data, nil)
	result = append(nonce, result...)

	return result, nil
}

func (c *AESGCMCrypt) Decrypt(data []byte) ([]byte, error) {
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

func (c *AESGCMCrypt) Method() Method {
	return MethodAESGCM
}
