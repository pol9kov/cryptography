package aes256_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"nornickel/cryptography/aes256"
)

// testDecrypt encrypt text with the passphrase
func testDecrypt(t *testing.T, encrypted string, pass string, expect string) {
	plaintext := aes256.Decrypt(encrypted, pass)

	require.Equal(t, expect, plaintext)

	return
}

// testEncryptDecrypt encrypt and then decrypt text with the passphrase
func testEncryptDecrypt(t *testing.T, plaintext string, pass string) {
	encrypted := aes256.Encrypt(plaintext, pass)

	testDecrypt(t, encrypted, pass, plaintext)

	return
}

func TestDecrypt1(t *testing.T) {
	testDecrypt(t,
		"U2FsdGVkX1+Z9xSlpZGuO2zo51XUtsCGZPs8bKQ/jYg=",
		"pass",
		"test")
}

func TestDecryptSpecialSymbols(t *testing.T) {
	testDecrypt(t,
		"U2FsdGVkX18z+AAtII5UURkNCVtXllxir5sL+dmEUmjhTM6jzaY651xVDFAieQpgXUyh/bCtlPFm2snn/32kOx2hrR6NS5Xrow4OKHUbwS0=",
		"哈罗 こんにちわ Акїў 😺",
		"{\"Д\": \"@#$%^&*( 🤡👌 哈罗 こんにちわ Акїў\"}")
}

func TestEncryptDecrypt(t *testing.T) {
	testEncryptDecrypt(t,
		"123123123",
		"asd")
}

func TestEncryptDecryptSpecialSymbols(t *testing.T) {
	testEncryptDecrypt(t,
		"{\"Д\": \"@#$%^&*( 🤡👌 哈罗 こんにちわ Акїў\"}",
		"哈罗 こんにちわ Акїў 😺")
}
