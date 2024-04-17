package elgamal

import (
	"AAA/curve25519"
	"bytes"
	"log"

	"go.dedis.ch/kyber/v3/util/random"
)

func elga_test() {
	// suite := suites.MustFind("Ed25519")
	suite := curve25519.NewBlakeSHA256Curve25519(false)
	secret, public := NewKeyPair(suite, random.New())
	msg := []byte("hello")
	rP, cipherText, err := Encrypt(suite, public, msg)
	if err != nil {
		log.Println(err)
		return
	}
	msg2, err := Decrypt(suite, rP, cipherText, secret)
	if err != nil {
		log.Println(err)
	}
	if bytes.Compare(msg, msg2) == 0 {
		log.Println("success")
	} else {
		log.Println("failed")
	}
}
