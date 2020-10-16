package strobe_test

import (
	"bytes"
	"fmt"

	"github.com/sammyne/strobe"
)

func ExampleStrobe_PRF() {
	const (
		proto         = "PRF streaming demo"
		securityLevel = strobe.Bit128
		key           = "hello-world"
	)

	s, err := strobe.New(proto, securityLevel)
	if err != nil {
		panic(fmt.Sprintf("failed to initialize encryptor: %v", err))
	}

	if err := s.KEY([]byte(key), false); err != nil {
		panic(fmt.Sprintf("fail to KEY: %v", err))
	}

	s2 := s.Clone()

	var prf1 [32]byte
	if err := s.PRF(prf1[:], false); err != nil {
		panic(fmt.Sprintf("fail to PRF: %v", err))
	}
	fmt.Printf("%x\n", prf1[:])

	{ // first 20 bytes
		var prf2 [20]byte
		if err := s2.PRF(prf2[:], false); err != nil {
			panic(fmt.Sprintf("fail to PRF2: %v", err))
		}
		fmt.Printf("%x\n", prf2[:])

		if !bytes.Equal(prf1[:len(prf2)], prf2[:]) {
			panic(fmt.Sprintf("invalid prefix: expect %x, got %x", prf1[:len(prf2)], prf2[:]))
		}
	}

	{ // last 12 bytes
		var prf2 [12]byte
		if err := s2.PRF(prf2[:], true); err != nil {
			panic(fmt.Sprintf("fail to PRF2: %v", err))
		}
		fmt.Printf("%x\n", prf2[:])

		if !bytes.Equal(prf1[len(prf1)-len(prf2):], prf2[:]) {
			panic(fmt.Sprintf("invalid prefix: expect %x, got %x", prf1[:len(prf2)], prf2[:]))
		}
	}

	// Output:
	// 0b8bc840017bf7f3cd4493eae67ac4504fc7f60a15e2d9f576f1a3e947193f7e
	// 0b8bc840017bf7f3cd4493eae67ac4504fc7f60a
	// 15e2d9f576f1a3e947193f7e
}
