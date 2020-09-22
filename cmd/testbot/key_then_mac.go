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
	Key  []byte // data input for AD
	MAC  []byte // PRF out
	Meta bool
}

func main() {
	testVectors := []TestVector{
		{Proto: "strobe-go-128", SecurityLevel: 128},
		{Proto: "strobe-go-256", SecurityLevel: 256},
	}

	for i, v := range testVectors {
		for j := 0; j < 512; j++ {
			data := mustRandBytes(j)

			key := make([]byte, len(data))

			meta := [2]bool{false, true}
			for _, m := range meta {
				copy(key, data)

				s := strobe.InitStrobe(v.Proto, v.SecurityLevel)
				s.KEY(key)
				mac := s.Send_MAC(m, 32)

				c := TestCase{Key: data, MAC: mac, Meta: m}
				testVectors[i].Cases = append(testVectors[i].Cases, c)
			}
		}
	}

	out, err := json.MarshalIndent(testVectors, "", "  ")
	if err != nil {
		panic(err)
	}

	if err := ioutil.WriteFile("key_then_mac.json", out, 0644); err != nil {
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
