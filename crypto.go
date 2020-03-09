package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
)

func SignScp11(command []byte, tag byte, macKey []byte, chainingIn []byte) (signed []byte, chainingOut []byte) {
	// add chaining
	dataToSign := append(command, chainingIn...)

	// calculate hash
	chainingOut = sha1.New().Sum(dataToSign)

	// prepare output
	signed = append(command, chainingOut[0:8]...)

	return signed, chainingOut
}

func EncryptScp11(commandID byte, command []byte, encKey []byte) (encrypted []byte) {
	// pad the data
	command = paddingISO9797Method2(command)

	// prepare IV
	iv := make([]byte, 16)
	iv[15] = commandID

	// encrypt the data
	block, _ := aes.NewCipher(encKey)
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(command, command)

	return command
}

func paddingISO9797Method2(in []byte) []byte {
	paddingLength := len(in) % 16
	if paddingLength == 0 {
		paddingLength = 16
	} else {
		paddingLength = 16 - paddingLength
	}

	out := make([]byte, len(in)+paddingLength)
	copy(out, in)
	out[len(in)] = 0x80
	return out
}
