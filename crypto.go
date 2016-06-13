package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
)

const (
	KeySize = 32 // aes-256
)

func MakeCipher(key []byte) (cipher.AEAD, error) {
	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, err
	}
	return aesgcm, nil
}

func EncryptMessage(plaintext []byte, key []byte) ([]byte, error) {
	cipher, err := MakeCipher(key)
	if err != nil {
		return nil, err
	}

	zeroNonce := make([]byte, cipher.NonceSize())
	ciphertext := cipher.Seal(nil, zeroNonce, plaintext, nil)
	return ciphertext, nil
}

func EncryptSessionKey(skey []byte, pubkeys []SSHKey) (map[string][]byte, error) {
	ciphers := make(map[string][]byte)

	for _, key := range pubkeys {
		ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, key.PublicKey, skey)
		if err != nil {
			return nil, err
		}
		ciphers[key.Fingerprint] = ciphertext
	}
	return ciphers, nil
}

func getRandomBytes(rlen int) ([]byte, error) {
	bytes := make([]byte, rlen)
	if _, err := rand.Read(bytes); err != nil {
		return nil, err
	}
	return bytes, nil
}

func DecryptMessage(ciphertext []byte, key []byte) ([]byte, error) {
	cipher, err := MakeCipher(key)
	if err != nil {
		return nil, err
	}
	zeroNonce := make([]byte, cipher.NonceSize())
	return cipher.Open(nil, zeroNonce, ciphertext, nil)
}

func DecryptSessionKey(skey []byte, privkey rsa.PrivateKey) ([]byte, error) {
	key := make([]byte, KeySize)
	return key, rsa.DecryptPKCS1v15SessionKey(rand.Reader, &privkey, skey, key)
}
