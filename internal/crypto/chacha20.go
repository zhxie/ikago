package crypto

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"golang.org/x/crypto/chacha20poly1305"
)

// ChaCha20Poly1305Crypto describes an ChaCha20-Poly1305 crypto
type ChaCha20Poly1305Crypto struct {
	aead cipher.AEAD
}

// CreateChaCha20Poly1305Crypto returns an ChaCha20-Poly1305 crypto by given key
func CreateChaCha20Poly1305Crypto(key []byte) (*ChaCha20Poly1305Crypto, error) {
	// AEAD
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("new aead: %w", err)
	}

	return &ChaCha20Poly1305Crypto{aead: aead}, nil
}

func (c *ChaCha20Poly1305Crypto) Encrypt(data []byte) ([]byte, error) {
	nonce, err := GenerateNonce(c.aead.NonceSize())
	if err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	result := c.aead.Seal(nil, nonce, data, nil)
	result = append(nonce, result...)

	return result, nil
}

func (c *ChaCha20Poly1305Crypto) Decrypt(data []byte) ([]byte, error) {
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

func (c *ChaCha20Poly1305Crypto) Method() Method {
	return MethodChaCha20Poly1305
}

// XChaCha20Poly1305Crypto describes an XChaCha20-Poly1305 crypto
type XChaCha20Poly1305Crypto struct {
	aead cipher.AEAD
}

// CreateXChaCha20Poly1305Crypto returns an XChaCha20-Poly1305 crypto by given key
func CreateXChaCha20Poly1305Crypto(key []byte) (*XChaCha20Poly1305Crypto, error) {
	// AEAD
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		fmt.Errorf("new aead: %w", err)
	}

	return &XChaCha20Poly1305Crypto{aead: aead}, nil
}

func (c *XChaCha20Poly1305Crypto) Encrypt(data []byte) ([]byte, error) {
	nonce, err := GenerateNonce(c.aead.NonceSize())
	if err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	result := c.aead.Seal(nil, nonce, data, nil)
	result = append(nonce, result...)

	return result, nil
}

func (c *XChaCha20Poly1305Crypto) Decrypt(data []byte) ([]byte, error) {
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

func (c *XChaCha20Poly1305Crypto) Method() Method {
	return MethodXChaCha20Poly1305
}
