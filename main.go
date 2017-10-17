package main

import (
	"github.com/spacemonkeygo/openssl"
	"log"
	"encoding/base64"
)


type Crypter struct {
	key    []byte
	iv     []byte
	cipher *openssl.Cipher
}

func NewCrypter(key []byte, iv []byte) (*Crypter, error) {
	cipher, err := openssl.GetCipherByName("aes-256-cfb8")
	if err != nil {
		return nil, err
	}

	return &Crypter{key, iv, cipher}, nil
}

func (c *Crypter) Encrypt(input []byte) ([]byte, error) {
	ctx, err := openssl.NewEncryptionCipherCtx(c.cipher, nil, c.key, c.iv)
	if err != nil {
		return nil, err
	}

	cipherbytes, err := ctx.EncryptUpdate(input)
	if err != nil {
		return nil, err
	}

	finalbytes, err := ctx.EncryptFinal()
	if err != nil {
		return nil, err
	}

	cipherbytes = append(cipherbytes, finalbytes...)
	return cipherbytes, nil
}

func (c *Crypter) Decrypt(input []byte) ([]byte, error) {
	ctx, err := openssl.NewDecryptionCipherCtx(c.cipher, nil, c.key, c.iv)
	if err != nil {
		return nil, err
	}

	cipherbytes, err := ctx.DecryptUpdate(input)
	if err != nil {
		return nil, err
	}

	finalbytes, err := ctx.DecryptFinal()
	if err != nil {
		return nil, err
	}

	cipherbytes = append(cipherbytes, finalbytes...)
	return cipherbytes, nil
}

func main() {
	// same key and initialization vector as in ruby example
	key := []byte("ee31b7ab8872d7ba57c9ad7afc9c527c")
	iv  := []byte("1234567890123450")

	// Initialize new crypter struct. Errors are ignored.
	crypter, _ := NewCrypter(key, iv)

	// Lets encode plaintext using the same key and iv.
	// This will produce the very same result: "RanFyUZSP9u/HLZjyI5zXQ=="
	encoded, _ := crypter.Encrypt([]byte(`{"uid":"1","username":"admin"}`))
	log.Println(base64.StdEncoding.EncodeToString(encoded))

	// Decode previous result. Should print "hello world"
	decoded, _ := crypter.Decrypt(encoded)
	log.Printf("%s\n", decoded)
}

