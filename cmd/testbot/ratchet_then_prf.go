// +build ignore

package main

import (
	"encoding/json"
	"io/ioutil"

	"github.com/mimoo/StrobeGo/strobe"
)

type TestVector struct {
	Proto         string
	SecurityLevel int
	Cases         []TestCase
}

type TestCase struct {
	Length int    // data input for AD
	PRF    []byte // PRF out
}

func main() {
	testVectors := []TestVector{
		{Proto: "strobe-go-128", SecurityLevel: 128},
		{Proto: "strobe-go-256", SecurityLevel: 256},
	}

	for i, v := range testVectors {
		for j := 1; j <= 512; j++ {
			s := strobe.InitStrobe(v.Proto, v.SecurityLevel)
			s.RATCHET(j)
			prf := s.PRF(32)

			c := TestCase{Length: j, PRF: prf}
			testVectors[i].Cases = append(testVectors[i].Cases, c)
		}
	}

	out, err := json.MarshalIndent(testVectors, "", "  ")
	if err != nil {
		panic(err)
	}

	if err := ioutil.WriteFile("ratchet_then_prf.json", out, 0644); err != nil {
		panic(err)
	}
}
