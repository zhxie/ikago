package crypto

import (
	"fmt"
	"strings"
)

// Method describes the method of the encryption
type Method int

const (
	// MethodPlain describes the encryption is in plain which will not encrypt the data
	MethodPlain Method = iota
	// MethodAESCFB describes the encryption is in AES-CFB
	MethodAESCFB
	// MethodAESGCM describes the encryption is in AES-GCM
	MethodAESGCM
	// MethodChaCha20Poly1305 describes the encryption is in ChaCha20-Poly1305
	MethodChaCha20Poly1305
	// MethodXChaCha20Poly1305 describes the encryption is in XChaCha20-Poly1305
	MethodXChaCha20Poly1305
)

// Crypto describes crypto of encryption
type Crypto interface {
	// Prepare implements a method prepares the crypto
	Prepare() error
	// Encrypt returns the encrypted data
	Encrypt([]byte) ([]byte, error)
	// Decrypt returns the decrypted data
	Decrypt([]byte) ([]byte, error)
	// Method returns the method of crypto
	Method() Method
}

func ParseCrypto(method, password string) (Crypto, error) {
	var c Crypto
	switch strings.ToLower(method) {
	case "plain":
		c = &PlainCrypto{}
	case "aes-128-gcm":
		c = &AESGCMCrypto{Key: DeriveKey(password, 16)}
	case "aes-192-gcm":
		c = &AESGCMCrypto{Key: DeriveKey(password, 24)}
	case "aes-256-gcm":
		c = &AESGCMCrypto{Key: DeriveKey(password, 32)}
	case "chacha20-poly1305":
		c = &ChaCha20Poly1305Crypto{Key: DeriveKey(password, 32)}
	case "xchacha20-poly1305":
		c = &XChaCha20Poly1305Crypto{Key: DeriveKey(password, 32)}
	default:
		return nil, fmt.Errorf("parse crypto: %w", fmt.Errorf("method %s not support", method))
	}

	// Prepare the crypto
	err := c.Prepare()
	if err != nil {
		return nil, fmt.Errorf("parse crypto: %w", err)
	}

	return c, nil
}
