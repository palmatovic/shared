package util

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"os"
)

func ReadEncryptedPasswordFromFile(filename string, key []byte) (string, error) {
	// Read the encrypted file contents
	ciphertext, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}

	// Decode the base64 encoded ciphertext
	ciphertextDec, err := base64.StdEncoding.DecodeString(string(ciphertext))
	if err != nil {
		return "", err
	}

	// Initialize the AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Determine the initialization vector length
	iv := make([]byte, aes.BlockSize)
	if len(ciphertextDec) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}
	copy(iv, ciphertextDec[:aes.BlockSize])

	// Decrypt the ciphertext
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertextDec[aes.BlockSize:], ciphertextDec[aes.BlockSize:])

	// Remove the padding length
	padding := ciphertextDec[len(ciphertextDec)-1]
	if int(padding) > len(ciphertextDec) {
		return "", errors.New("invalid padding")
	}
	ciphertextDec = ciphertextDec[:len(ciphertextDec)-int(padding)]

	// Convert the decrypted result to a string and return it
	return string(ciphertextDec), nil
}
