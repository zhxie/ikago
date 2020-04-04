package crypto

import (
	"fmt"
	"strconv"
	"strings"
)

// Method describes the method of the encryption.
type Method int

const (
	// MethodPlain describes the encryption is in plain which will not encrypt the data.
	MethodPlain Method = iota
	// MethodAESCFB describes the encryption is in AES-CFB.
	MethodAESCFB
	// MethodAESGCM describes the encryption is in AES-GCM.
	MethodAESGCM
	// MethodChaCha20Poly1305 describes the encryption is in ChaCha20-Poly1305.
	MethodChaCha20Poly1305
	// MethodXChaCha20Poly1305 describes the encryption is in XChaCha20-Poly1305.
	MethodXChaCha20Poly1305
)

func (m Method) String() string {
	switch m {
	case MethodPlain:
		return "Plain"
	case MethodAESCFB:
		return "AES-CFB"
	case MethodAESGCM:
		return "AES-GCM"
	case MethodChaCha20Poly1305:
		return "ChaCha20-Poly1305"
	case MethodXChaCha20Poly1305:
		return "XChaCha20-Poly1305"
	default:
		return strconv.Itoa(int(m))
	}
}

// Crypt describes crypt of encryption.
type Crypt interface {
	// Encrypt returns the encrypted data.
	Encrypt([]byte) ([]byte, error)
	// Decrypt returns the decrypted data.
	Decrypt([]byte) ([]byte, error)
	// Method returns the method of crypt.
	Method() Method
	// Cost returns the size of cost.
	Cost() int
}

// ParseCrypt returns a crypt by given method and password.
func ParseCrypt(method, password string) (Crypt, error) {
	var (
		err error
		c   Crypt
	)

	switch strings.ToLower(method) {
	case "plain":
		c = CreatePlainCrypt()
	case "aes-128-gcm":
		c, err = CreateAESGCMCrypt(DeriveKey(password, 16))
	case "aes-192-gcm":
		c, err = CreateAESGCMCrypt(DeriveKey(password, 24))
	case "aes-256-gcm":
		c, err = CreateAESGCMCrypt(DeriveKey(password, 32))
	case "chacha20-poly1305":
		c, err = CreateChaCha20Poly1305Crypt(DeriveKey(password, 32))
	case "xchacha20-poly1305":
		c, err = CreateXChaCha20Poly1305Crypt(DeriveKey(password, 32))
	default:
		return nil, fmt.Errorf("method %s not support", method)
	}
	if err != nil {
		return nil, err
	}

	return c, nil
}
