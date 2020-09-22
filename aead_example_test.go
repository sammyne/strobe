package strobe_test

import (
	"bytes"
	"fmt"

	"github.com/sammyne/strobe"
)

func ExampleAEAD() {
	const (
		proto         = "AEAD demo"
		securityLevel = strobe.Bit128
		plaintext     = "hello world"
		nonce         = "this is a nonce"
		key           = "secret"
	)

	// encrypt
	encryptor, err := strobe.New(proto, securityLevel)
	if err != nil {
		panic(fmt.Sprintf("failed to initialize encryptor: %v", err))
	}

	if err := encryptor.KEY([]byte(key), false); err != nil {
		panic(fmt.Sprintf("fail to add key to encryptor: %v", err))
	}

	opts := &strobe.Options{}

	ciphertext, err := encryptor.SendENC([]byte(plaintext), opts)
	if err != nil {
		panic(fmt.Sprintf("SendENC failed: %v", err))
	}

	if err := encryptor.AD([]byte(nonce), opts); err != nil {
		panic(fmt.Sprintf("AD failed: %v", err))
	}

	mac, err := encryptor.SendMAC(32, opts)
	if err != nil {
		panic(fmt.Sprintf("SendMAC failed: %v", err))
	}

	// decrypt
	decryptor, err := strobe.New(proto, securityLevel)
	if err != nil {
		panic(fmt.Sprintf("failed to initialize decryptor: %v", err))
	}

	if err := decryptor.KEY([]byte(key), false); err != nil {
		panic(fmt.Sprintf("fail to add key to encryptor: %v", err))
	}

	recovered, err := decryptor.RecvENC(ciphertext, opts)
	if err != nil {
		panic(fmt.Sprintf("RecvMAC failed: %v", err))
	}

	if !bytes.Equal([]byte(plaintext), recovered) {
		panic(fmt.Sprintf("invalid plaintext recovered: expect %x, got %x", plaintext, recovered))
	}

	if err := decryptor.AD([]byte(nonce), opts); err != nil {
		panic(fmt.Sprintf("decryptor AD failed: %v", err))
	}

	if err := decryptor.RecvMAC(mac, opts); err != nil {
		panic(fmt.Sprintf("invalid MAC: %v", err))
	}

	// Output:
	//
}
