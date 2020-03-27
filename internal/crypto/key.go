package crypto

import (
	"crypto/md5"
	"crypto/rand"
	"io"
)

// DeriveKey derives a key from a string of password.
func DeriveKey(password string, length int) []byte {
	var key, prev []byte

	h := md5.New()

	for len(key) < length {
		h.Write(prev)
		h.Write([]byte(password))
		key = h.Sum(key)
		prev = key[len(key)-h.Size():]
		h.Reset()
	}

	return key[:length]
}

// GenerateIV generates a random IV of the given size.
func GenerateIV(size int) ([]byte, error) {
	iv := make([]byte, size)

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	return iv, nil
}

// GenerateNonce generates a random nonce of the given size.
func GenerateNonce(size int) ([]byte, error) {
	nonce := make([]byte, size)

	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return nonce, nil
}
