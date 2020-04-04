package crypto

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
)

// ChaCha20Poly1305Crypt describes an ChaCha20-Poly1305 crypt.
type ChaCha20Poly1305Crypt struct {
	aead cipher.AEAD
}

// CreateChaCha20Poly1305Crypt returns an ChaCha20-Poly1305 crypt by given key.
func CreateChaCha20Poly1305Crypt(key []byte) (*ChaCha20Poly1305Crypt, error) {
	// AEAD
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("new aead: %w", err)
	}

	return &ChaCha20Poly1305Crypt{aead: aead}, nil
}

func (c *ChaCha20Poly1305Crypt) Encrypt(data []byte) ([]byte, error) {
	nonce, err := GenerateNonce(c.aead.NonceSize())
	if err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	result := c.aead.Seal(nil, nonce, data, nil)
	result = append(nonce, result...)

	return result, nil
}

func (c *ChaCha20Poly1305Crypt) Decrypt(data []byte) ([]byte, error) {
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

func (c *ChaCha20Poly1305Crypt) Method() Method {
	return MethodChaCha20Poly1305
}

func (c *ChaCha20Poly1305Crypt) Cost() int {
	return c.aead.NonceSize() + poly1305.TagSize
}

// XChaCha20Poly1305Crypt describes an XChaCha20-Poly1305 crypt.
type XChaCha20Poly1305Crypt struct {
	aead cipher.AEAD
}

// CreateXChaCha20Poly1305Crypt returns an XChaCha20-Poly1305 crypt by given key.
func CreateXChaCha20Poly1305Crypt(key []byte) (*XChaCha20Poly1305Crypt, error) {
	// AEAD
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("new aead: %w", err)
	}

	return &XChaCha20Poly1305Crypt{aead: aead}, nil
}

func (c *XChaCha20Poly1305Crypt) Encrypt(data []byte) ([]byte, error) {
	nonce, err := GenerateNonce(c.aead.NonceSize())
	if err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	result := c.aead.Seal(nil, nonce, data, nil)
	result = append(nonce, result...)

	return result, nil
}

func (c *XChaCha20Poly1305Crypt) Decrypt(data []byte) ([]byte, error) {
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

func (c *XChaCha20Poly1305Crypt) Method() Method {
	return MethodXChaCha20Poly1305
}

func (c *XChaCha20Poly1305Crypt) Cost() int {
	return c.aead.NonceSize() + poly1305.TagSize
}
