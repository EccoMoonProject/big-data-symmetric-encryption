package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/nacl/secretbox"
	"io/ioutil"
	"log"
	"net/http"
)

// TODO, make this into a struct that implements crypto.Symmetric.

const (
	nonceLen  = 24
	secretLen = 32
)

// secret must be 32 bytes long. Use something like Sha256(Bcrypt(passphrase))
// The ciphertext is (secretbox.Overhead + 24) bytes longer than the plaintext.
func EncryptSymmetric(plaintext []byte, secret []byte) (ciphertext []byte) {
	if len(secret) != secretLen {
		panic(fmt.Sprintf("Secret must be 32 bytes long, got len %v", len(secret)))
	}
	nonce := randBytes(nonceLen)
	nonceArr := [nonceLen]byte{}
	copy(nonceArr[:], nonce)
	secretArr := [secretLen]byte{}
	copy(secretArr[:], secret)
	ciphertext = make([]byte, nonceLen+secretbox.Overhead+len(plaintext))
	copy(ciphertext, nonce)
	secretbox.Seal(ciphertext[nonceLen:nonceLen], plaintext, &nonceArr, &secretArr)
	return ciphertext
}

// secret must be 32 bytes long. Use something like Sha256(Bcrypt(passphrase))
// The ciphertext is (secretbox.Overhead + 24) bytes longer than the plaintext.
func DecryptSymmetric(ciphertext []byte, secret []byte) (plaintext []byte, err error) {
	if len(secret) != secretLen {
		panic(fmt.Sprintf("Secret must be 32 bytes long, got len %v", len(secret)))
	}
	if len(ciphertext) <= secretbox.Overhead+nonceLen {
		return nil, errors.New("ciphertext is too short")
	}
	nonce := ciphertext[:nonceLen]
	nonceArr := [nonceLen]byte{}
	copy(nonceArr[:], nonce)
	secretArr := [secretLen]byte{}
	copy(secretArr[:], secret)
	plaintext = make([]byte, len(ciphertext)-nonceLen-secretbox.Overhead)
	_, ok := secretbox.Open(plaintext[:0], ciphertext[nonceLen:], &nonceArr, &secretArr)
	if !ok {
		return nil, errors.New("ciphertext decryption failed")
	}
	return plaintext, nil
}

// This only uses the OS's randomness
func randBytes(numBytes int) []byte {
	b := make([]byte, numBytes)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}

type people struct {
	Number int `json:"number"`
}

func encrypt(_url string, secret []byte) []byte {

	response, err := http.Get(_url)
	if err != nil {
		log.Fatal(err)

	}

	defer response.Body.Close()

	// read data from response body
	data, err := ioutil.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}

	// convert data to string
	dataString := string(data)

	// convert string to byte

	dataByte := []byte(dataString)

	// encrypt data

	encryptedData := EncryptSymmetric(dataByte, secret)

	return encryptedData

}

func decrypt(encryptedData []byte, secret []byte) []byte {

	// decrypt data

	decryptedData, err := DecryptSymmetric(encryptedData, secret)

	if err != nil {
		log.Fatal(err)
	}

	// convert byte to string

	decryptedDataString := string(decryptedData)

	// print data

	fmt.Println(decryptedDataString)

	return decryptedData

}

func main() {
	url := "https://countriesnow.space/api/v0.1/countries/population/cities"

	// generate key
	secret := randBytes(secretLen)
	secretString := fmt.Sprintf("%x", secret)

	secretFile, _ := json.MarshalIndent(secretString, "", " ")
	err := ioutil.WriteFile("secret.txt", secretFile, 0644)
	if err != nil {
		log.Fatal(err)
	}

	encryptedData := encrypt(url, secret)
	encryptedDataString := fmt.Sprintf("%x", encryptedData)

	// decrypt data

	decryptedData := decrypt(encryptedData, secret)
	decryptedDataString := string(decryptedData)

	// write files
	encryptionFile, _ := json.MarshalIndent(encryptedDataString, "", " ")
	err_enc := ioutil.WriteFile("encryptedData.txt", encryptionFile, 0644)
	if err_enc != nil {
		log.Fatal(err_enc)
	}

	decryptionFile, _ := json.MarshalIndent(decryptedDataString, "", " ")
	err_dec := ioutil.WriteFile("decryptedData.txt", decryptionFile, 0644)
	if err_dec != nil {
		log.Fatal(err_dec)
	}

}
