package aes256

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"io"

	"github.com/pkg/errors"
)

// Encrypts text with the passphrase
func EncryptText(plaintext string, pass string) (string, error) {
	fmt.Printf("plaintext %s\n pass %s\n", plaintext, pass)

	salt := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", errors.Wrap(err, "failed to read reader")
	}
	fmt.Printf("salt %s\n ", salt)

	key, iv := __DeriveKeyAndIv(pass, string(salt))
	fmt.Printf("salted key %s\n ", key)

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", errors.Wrap(err, "failed to create cipher from key")
	}

	pad := __PKCS7Padding([]byte(plaintext), block.BlockSize())
	ecb := cipher.NewCBCEncrypter(block, []byte(iv))
	encrypted := make([]byte, len(pad))
	ecb.CryptBlocks(encrypted, pad)

	fmt.Printf("encripted %s", encrypted)

	enc := b64.StdEncoding.EncodeToString([]byte("Salted__" + string(salt) + string(encrypted)))
	fmt.Printf("salted encripted %s", enc)
	return b64.StdEncoding.EncodeToString([]byte("Salted__" + string(salt) + string(encrypted))), nil
}

// Decrypts encrypted text with the passphrase
func DecryptText(encrypted string, pass string) (string, error) {

	fmt.Printf("encrypted blob %s\n pass %s\n", encrypted, pass)

	ct, err := b64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", errors.Wrap(err, "failed to decode")
	}
	if len(ct) < 16 || string(ct[:8]) != "Salted__" {
		return "", errors.New("incorrect input")
	}
	fmt.Printf("ct %s\n", ct)

	salt := ct[8:16]
	ct = ct[16:]
	key, iv := __DeriveKeyAndIv(pass, string(salt))
	fmt.Printf("key %s\n", key)

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", errors.Wrap(err, "failed to create cipher from key")
	}

	cbc := cipher.NewCBCDecrypter(block, []byte(iv))
	dst := make([]byte, len(ct))
	cbc.CryptBlocks(dst, ct)
	fmt.Printf("dst %s\n", dst)

	return string(__PKCS7Trimming(dst)), nil
}

// Encrypts interface with the passphrase
func Encrypt(entity interface{}, pass string) (string, error) {
	blob, err := json.Marshal(entity)
	if err != nil {
		return "", errors.Wrap(err, "failed to marshal entity")
	}

	return EncryptText(string(blob), pass)
}

// Decrypts encrypted text in interface with the passphrase
func Decrypt(encrypted string, entity interface{}, pass string) error {

	s, err := DecryptText(encrypted, pass)
	if err != nil {
		return errors.Wrap(err, "failed to decrypt")
	}

	err = json.Unmarshal([]byte(s), entity)
	if err != nil {
		return errors.Wrap(err, "failed to unmarshal encrypted part")
	}

	return nil
}

func __PKCS7Padding(cipher []byte, blockSize int) []byte {
	padding := blockSize - len(cipher)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(cipher, padtext...)
}

func __PKCS7Trimming(encrypt []byte) []byte {
	padding := encrypt[len(encrypt)-1]
	fmt.Printf("padding %v\n", len(encrypt)-int(padding))
	return encrypt[:len(encrypt)-int(padding)]
}

func __DeriveKeyAndIv(pass string, salt string) (string, string) {
	salted := ""
	dI := ""

	for len(salted) < 48 {
		md := md5.New()
		md.Write([]byte(dI + pass + salt))
		dM := md.Sum(nil)
		dI = string(dM[:16])
		salted = salted + dI
	}

	key := salted[0:32]
	iv := salted[32:48]

	return key, iv
}
