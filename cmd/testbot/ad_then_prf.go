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
	Data     []byte // data input for AD
	WithMeta bool   // with meta or not
	PRF      []byte // PRF out
}

func main() {
	testVectors := []TestVector{
		{Proto: "strobe-go-128", SecurityLevel: 128},
		{Proto: "strobe-go-256", SecurityLevel: 256},
	}

	for i, v := range testVectors {
		for j := 0; j < 512; j++ {
			data := mustRandBytes(j)

			{
				d := make([]byte, len(data))
				copy(d, data)

				s := strobe.InitStrobe(v.Proto, v.SecurityLevel)
				s.AD(false, data)
				prf := s.PRF(32)

				c := TestCase{Data: data, PRF: prf}
				testVectors[i].Cases = append(testVectors[i].Cases, c)
			}

			{
				s := strobe.InitStrobe(v.Proto, v.SecurityLevel)
				s.AD(true, data)
				prf := s.PRF(32)

				c := TestCase{Data: data, WithMeta: true, PRF: prf}
				testVectors[i].Cases = append(testVectors[i].Cases, c)
			}
		}
	}

	out, err := json.MarshalIndent(testVectors, "", "  ")
	if err != nil {
		panic(err)
	}

	if err := ioutil.WriteFile("ad_then_prf.json", out, 0644); err != nil {
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
