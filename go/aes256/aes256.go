package aes256

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	b64 "encoding/base64"
	"encoding/json"
	"io"

	"github.com/pkg/errors"
)

// Encrypts text with the passphrase
func EncryptText(plaintext string, pass []byte) (string, error) {

	salt := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", errors.Wrap(err, "failed to read reader")
	}

	key, iv := __DeriveKeyAndIv(string(pass), string(salt))

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", errors.Wrap(err, "failed to create cipher from key")
	}

	pad := __PKCS7Padding([]byte(plaintext), block.BlockSize())
	ecb := cipher.NewCBCEncrypter(block, []byte(iv))
	encrypted := make([]byte, len(pad))
	ecb.CryptBlocks(encrypted, pad)

	return b64.StdEncoding.EncodeToString([]byte("Salted__" + string(salt) + string(encrypted))), nil
}

// Decrypts encrypted text with the passphrase
func DecryptText(encrypted string, pass []byte) (string, error) {

	ct, err := b64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", errors.Wrap(err, "failed to decode")
	}
	if len(ct) < 16 || string(ct[:8]) != "Salted__" {
		return "", errors.New("incorrect input")
	}

	salt := ct[8:16]
	ct = ct[16:]
	key, iv := __DeriveKeyAndIv(string(pass), string(salt))

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", errors.Wrap(err, "failed to create cipher from key")
	}

	cbc := cipher.NewCBCDecrypter(block, []byte(iv))
	dst := make([]byte, len(ct))
	cbc.CryptBlocks(dst, ct)

	return __PKCS7Trimming(dst)
}

// Encrypts interface with the passphrase
func Encrypt(entity interface{}, pass []byte) (string, error) {
	blob, err := json.Marshal(entity)
	if err != nil {
		return "", errors.Wrap(err, "failed to marshal entity")
	}

	return EncryptText(string(blob), pass)
}

// Decrypts encrypted text in interface with the passphrase
func Decrypt(encrypted string, entity interface{}, pass []byte) error {

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

func __PKCS7Trimming(encrypt []byte) (string, error) {
	padding := encrypt[len(encrypt)-1]
	if len(encrypt)-int(padding) < 0 {
		return "", errors.New("failed to trim")
	}
	return string(encrypt[:len(encrypt)-int(padding)]), nil
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
