// +build ignore

package main

import (
	"encoding/json"
	"io/ioutil"
	"math/rand"

	"github.com/mimoo/StrobeGo/strobe"
)

type TestVector struct {
	Proto         string
	SecurityLevel int
	Cases         []TestCase
}

type TestCase struct {
	Key        []byte
	Meta       bool
	Plaintext  []byte
	Ciphertext []byte
}

func main() {
	testVectors := []TestVector{
		{Proto: "strobe-go-128", SecurityLevel: 128},
		{Proto: "strobe-go-256", SecurityLevel: 256},
	}

	for i, v := range testVectors {
		for j := 0; j < 512; j++ {
			key := mustRandBytes(32)

			meta := [2]bool{false, true}
			for _, m := range meta {
				s := strobe.InitStrobe(v.Proto, v.SecurityLevel)
				s.KEY(key)

				plaintext := mustRandBytes(j)
				ciphertext := s.Send_ENC_unauthenticated(m, plaintext)

				c := TestCase{
					Key:        key,
					Meta:       m,
					Plaintext:  plaintext,
					Ciphertext: ciphertext,
				}
				testVectors[i].Cases = append(testVectors[i].Cases, c)
			}
		}
	}

	out, err := json.MarshalIndent(testVectors, "", "  ")
	if err != nil {
		panic(err)
	}

	if err := ioutil.WriteFile("send_then_recv_enc.json", out, 0644); err != nil {
		panic(err)
	}
}

func init() {
	rand.Seed(0x123456)
}

func mustRandBytes(ell int) []byte {
	out := make([]byte, ell)
	if _, err := rand.Read(out); err != nil {
		panic(err)
	}

	return out
}
